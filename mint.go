package kdc

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"
	"unicode"

	"github.com/go-authn/kdc/internal/cammac"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Minting: a TGT for a person who proved themselves ELSEWHERE.
//
// An AS-REQ proves a long-term key (a password). A person who logs in with a
// passkey at go-authn/bridge has none, and is refused KDC_ERR_NULL_KEY. This
// path lets one trusted caller, bridge, ask this KDC for a TGT for a
// principal it has just authenticated, and returns it as a KRB-CRED
// (RFC 4120 5.8) the person's machine can load into its credential cache
// (Windows: LsaCallAuthenticationPackage KerbSubmitTicketMessage).
//
// What keeps it narrow:
//
//   - Off unless [Config.MintCallers] names who may ask; nothing is minted for
//     an unlisted or unauthenticated caller.
//   - The caller is authenticated by the TLS client certificate the listener
//     verified (a URI subjectAltName matched against MintCallers), never by a
//     header or a body field. A listener that does not ask for client
//     certificates mints nothing: the handler reads r.TLS.VerifiedChains.
//   - The principal must exist in the directory, as for an AS-REQ: a removed
//     person gets nothing, and the KDC's own TGS checks run on what comes back.
//   - The ticket is INITIAL | PRE-AUTHENT (the caller vouched), never
//     RENEWABLE, FORWARDABLE or PROXIABLE; its lifetime is the shortest of what
//     was asked, [Config.Lifetime] and [MaxMintLifetime].
//   - The session key is made here, from crypto/rand, and leaves this process
//     once, in the reply to the caller. It is never logged.
//
// The KRB-CRED carries the key in the clear (EncryptedData etype 0, RFC 4120
// 5.8.1 allows it): the transport, mutually authenticated TLS, is the
// encryption. See the threat model in the pull request that added this file.

// MaxMintLifetime is the longest TGT a mint request can get, whatever the
// caller asks and whatever [Config.Lifetime] says.
const MaxMintLifetime = 10 * time.Hour

// MintRequest is what a trusted caller sends.
type MintRequest struct {
	// Principal is the person's name exactly as the directory holds it.
	Principal string `json:"principal"`
	// LifetimeSeconds is how long the caller wants the TGT to last; zero means
	// as long as allowed. It is capped, never extended.
	LifetimeSeconds int64 `json:"lifetime_seconds,omitempty"`
	// Method is how the person logged in, which the KDC cannot know: passkey,
	// federated or machine. It is required when [Config.PAC] is set (it becomes
	// the TGT's authentication indicator and the PAC's minted SID), never
	// defaulted; optional, but checked, otherwise.
	Method string `json:"method,omitempty"`
}

// Errors Mint reports.
var (
	// ErrMintRefused reports a request that is not allowed: a bad name, a
	// principal this realm does not know.
	ErrMintRefused = errors.New("kdc: mint refused")
	// ErrMintDisabled reports a realm configured with no MintCallers.
	ErrMintDisabled = errors.New("kdc: minting is not enabled")
)

// Mint makes a TGT for req.Principal and returns it as a KRB-CRED. It does
// NOT authenticate the caller: [Server.MintHandler] does, and is what to
// expose. It exists as a method so that an in-process caller (a test, a
// supervisor holding both services) has no HTTP in between.
func (s *Server) Mint(req MintRequest) ([]byte, error) {
	if len(s.cfg.MintCallers) == 0 {
		return nil, ErrMintDisabled
	}
	if err := mintablePrincipal(req.Principal); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMintRefused, err)
	}
	indicator, known := mintMethods[req.Method]
	if (req.Method != "" && !known) || (req.Method == "" && s.cfg.PAC != nil) {
		return nil, ErrMintBadMethod
	}
	name := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{req.Principal}}
	id, err := s.lookup(name)
	if err != nil {
		if errors.Is(err, errDirectoryDown) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: this realm does not know that principal", ErrMintRefused)
	}

	life := min(s.cfg.lifetime(), MaxMintLifetime)
	if req.LifetimeSeconds > 0 {
		life = min(life, time.Duration(req.LifetimeSeconds)*time.Second)
	}
	if life < time.Minute {
		return nil, fmt.Errorf("%w: a lifetime under a minute is no ticket", ErrMintRefused)
	}
	start := now().UTC().Truncate(time.Second)
	end := start.Add(life)

	krbtgt := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", s.cfg.Realm}}
	_, kvno, err := s.cfg.Services.GetEncryptionKey(krbtgt, s.cfg.Realm, 0, defaultEtype)
	if err != nil {
		return nil, err
	}
	fl := types.NewKrbFlags()
	types.SetFlag(&fl, flags.Initial)
	types.SetFlag(&fl, flags.PreAuthent)
	var (
		tkt     messages.Ticket
		session types.EncryptionKey
	)
	if s.pacState() != nil {
		// D7: the TGT says it was minted, how, and for which uidNumber.
		tkt, session, err = s.newTGT(name, fl, start, start, end,
			cammac.Claims{Methods: []string{indicator}, UID: uidOf(id)})
	} else {
		tkt, session, err = messages.NewTicket(name, s.cfg.Realm, krbtgt, s.cfg.Realm,
			fl, s.cfg.Services, defaultEtype, kvno, start, start, end, time.Time{})
	}
	if err != nil {
		return nil, err
	}
	return marshalKRBCred(tkt, session, name, s.cfg.Realm, fl, start, end, krbtgt)
}

// mintablePrincipal says whether a name is one the directory could hold and
// that stays ONE name wherever it is printed or split.
func mintablePrincipal(p string) error {
	if p == "" || len(p) > 256 {
		return errors.New("a principal of 1 to 256 bytes")
	}
	for _, r := range p {
		if r == '/' || r == '\\' || r == ',' || r == '"' || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return fmt.Errorf("the principal holds %q", r)
		}
	}
	return nil
}

// marshalKRBCred builds the KRB-CRED of RFC 4120 5.8.1 for one ticket, its
// EncKrbCredPart unencrypted (etype 0). gokrb5 can read one and cannot write
// one.
func marshalKRBCred(tkt messages.Ticket, session types.EncryptionKey, cname types.PrincipalName,
	realm string, fl asn1.BitString, start, end time.Time, sname types.PrincipalName) ([]byte, error) {

	type credInfo struct {
		Key       types.EncryptionKey `asn1:"explicit,tag:0"`
		PRealm    string              `asn1:"generalstring,explicit,tag:1"`
		PName     types.PrincipalName `asn1:"explicit,tag:2"`
		Flags     asn1.BitString      `asn1:"explicit,tag:3"`
		AuthTime  time.Time           `asn1:"generalized,explicit,tag:4"`
		StartTime time.Time           `asn1:"generalized,explicit,tag:5"`
		EndTime   time.Time           `asn1:"generalized,explicit,tag:6"`
		SRealm    string              `asn1:"generalstring,explicit,tag:8"`
		SName     types.PrincipalName `asn1:"explicit,tag:9"`
	}
	type encPart struct {
		Info []credInfo `asn1:"explicit,tag:0"`
	}
	tb, err := tkt.Marshal()
	if err != nil {
		return nil, err
	}
	seq, err := asn1.Marshal(encPart{Info: []credInfo{{
		Key: session, PRealm: realm, PName: cname, Flags: fl,
		AuthTime: start, StartTime: start, EndTime: end, SRealm: realm, SName: sname,
	}}})
	if err != nil {
		return nil, err
	}
	enc, err := asn1.Marshal(types.EncryptedData{EType: 0, Cipher: derTLV(0x7d, seq)}) // [APPLICATION 29]
	if err != nil {
		return nil, err
	}
	ctx := func(n byte, b []byte) []byte { return derTLV(0xa0|n, b) }
	body := append(ctx(0, derTLV(0x02, []byte{5})), ctx(1, derTLV(0x02, []byte{22}))...)
	body = append(body, ctx(2, derTLV(0x30, tb))...)
	body = append(body, ctx(3, enc)...)
	return derTLV(0x76, derTLV(0x30, body)), nil // [APPLICATION 22]
}

// derTLV is one DER element: tag, length, content.
func derTLV(tag byte, content []byte) []byte {
	n := len(content)
	var l []byte
	switch {
	case n < 0x80:
		l = []byte{byte(n)}
	case n < 0x100:
		l = []byte{0x81, byte(n)}
	case n < 0x10000:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	default:
		l = []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(append([]byte{tag}, l...), content...)
}

// MintHandler is the HTTP face of [Server.Mint]: POST a JSON [MintRequest],
// receive the KRB-CRED (application/octet-stream).
//
// Serve it ONLY on a listener that demands and verifies client certificates
// (tls.RequireAndVerifyClientCert, ClientCAs = the callers' CA), on a unix
// socket or an internal interface, never on the KDC's public address. The
// handler refuses a request whose connection was not verified that way, so a
// listener that forgot mints nothing rather than minting for everybody.
func (s *Server) MintHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.MintCallers) == 0 {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		caller, ok := s.mintCaller(r)
		if !ok {
			s.logf("kdc: mint: refused a caller that is not on the list (%s)", callerLabel(r))
			http.Error(w, "not allowed", http.StatusForbidden)
			return
		}
		var req MintRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "the body is not a mint request", http.StatusBadRequest)
			return
		}
		cred, err := s.Mint(req)
		switch {
		case errors.Is(err, ErrMintBadMethod):
			http.Error(w, "method must be one of passkey, federated, machine", http.StatusBadRequest)
			return
		case errors.Is(err, ErrMintRefused):
			s.logf("kdc: mint: %s asked for %q: %v", caller, req.Principal, err)
			http.Error(w, "refused", http.StatusForbidden)
			return
		case err != nil:
			s.logf("kdc: mint: %s asked for %q: %v", caller, req.Principal, err)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		// The key is in the reply: never cached, never logged.
		s.logf("kdc: mint: %s was given a TGT for %q (asked %ds, 0 = the maximum)", caller, req.Principal, req.LifetimeSeconds)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(cred)
	})
}

// mintCaller returns who the verified client certificate says is calling, and
// whether that is on [Config.MintCallers].
func (s *Server) mintCaller(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", false
	}
	return matchCaller(r.TLS.VerifiedChains[0][0], s.cfg.MintCallers)
}

func matchCaller(leaf *x509.Certificate, allow []string) (string, bool) {
	for _, u := range leaf.URIs {
		if slices.Contains(allow, u.String()) {
			return u.String(), true
		}
	}
	return "", false
}

func callerLabel(r *http.Request) string {
	if r.TLS == nil {
		return "no TLS"
	}
	if len(r.TLS.VerifiedChains) == 0 {
		return "no verified client certificate"
	}
	return "a verified certificate with no allowed URI"
}
