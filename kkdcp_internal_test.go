package kdc

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// envelope is what a KKDCP client posts: the message with its length, and the
// realm. A test that builds it by hand does not depend on the code under test
// to encode what it then decodes.
func envelope(t testing.TB, msg []byte, realm string) []byte {
	t.Helper()
	k := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(k, uint32(len(msg)))
	copy(k[4:], msg)
	b, err := asn1.Marshal(proxyMessage{KerbMessage: k, TargetDomain: realm})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func postKKDCP(t testing.TB, h http.Handler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/KdcProxy", bytes.NewReader(body)))
	return rec
}

// replyOf unwraps a 200 answer to the Kerberos message it carries, checking
// the envelope on the way: prefix equal to the length, no target-domain.
func replyOf(t testing.TB, rec *httptest.ResponseRecorder) []byte {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/kerberos" {
		t.Fatalf("Content-Type %q", ct)
	}
	msg, realm, err := parseProxyMessage(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("the answer is not a KDC-PROXY-MESSAGE: %v", err)
	}
	if realm != "" {
		t.Fatalf("a server message carries no target-domain, got %q", realm)
	}
	return msg
}

// tcpExchange sends one message the way port 88 takes it and returns the reply.
func tcpExchange(t testing.TB, s *Server, msg []byte) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeTCP(ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msg)))
	if _, err := c.Write(append(hdr[:], msg...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(c, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// kkdcpRealm is a realm with alice, her key and what a TGS-REQ needs.
type kkdcpRealm struct {
	s     *Server
	asReq []byte // no pre-authentication: the KDC asks for it
	tgs   []byte // a TGS-REQ for nfs/localhost with a TGT of its own making
}

func newKKDCPRealm(t testing.TB) kkdcpRealm {
	t.Helper()
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	kt := keytab.New()
	for _, p := range []string{"krbtgt/" + testRealm, "nfs/localhost"} {
		if err := kt.AddEntry(p, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
			t.Fatal(err)
		}
	}
	// A *testing.F cannot Logf from inside its fuzz function.
	logf := func(string, ...any) {}
	if tt, ok := t.(*testing.T); ok {
		logf = tt.Logf
	}
	s, err := New(Config{Realm: testRealm, People: onlyOne{id}, Services: kt, Logf: logf})
	if err != nil {
		t.Fatal(err)
	}
	n := now().UTC()
	tgtName := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	client := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	tkt, sk, err := messages.NewTicket(client, testRealm, tgtName, testRealm, types.NewKrbFlags(),
		kt, defaultEtype, 2, n, n, n.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	tgs := signedTGSReq(t, tkt, sk, client, messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		Till:  n.Add(time.Hour), Nonce: 7, EType: []int32{defaultEtype}}, bodyChecksum(t, sk))
	return kkdcpRealm{s: s, asReq: asReq(t, "alice", []string{"krbtgt", testRealm}, nil), tgs: tgs}
}

// The same request gets the same answer on both transports. A TGS-REP is
// kept by the lookaside (replay.go) and a repeated request is answered with it
// byte for byte, so a request sent through the proxy and again to TCP 88 is
// answered identically exactly when the proxy handed it over unchanged. A
// KRB-ERROR is not kept (its time is the time of asking), so there the codes
// and texts are compared.
func TestKKDCPAnswersAsPort88Does(t *testing.T) {
	r := newKKDCPRealm(t)
	h := r.s.KKDCPHandler()
	viaProxy := replyOf(t, postKKDCP(t, h, envelope(t, r.tgs, testRealm)))
	if viaTCP := tcpExchange(t, r.s, r.tgs); !bytes.Equal(viaProxy, viaTCP) {
		t.Errorf("TGS-REQ: the proxy and TCP 88 answered differently\nproxy %x\ntcp   %x", viaProxy, viaTCP)
	}
	var a, b messages.KRBError
	if err := a.Unmarshal(replyOf(t, postKKDCP(t, h, envelope(t, r.asReq, testRealm)))); err != nil {
		t.Fatal(err)
	}
	if err := b.Unmarshal(tcpExchange(t, r.s, r.asReq)); err != nil {
		t.Fatal(err)
	}
	if a.ErrorCode != b.ErrorCode || a.EText != b.EText || !bytes.Equal(a.EData, b.EData) || a.SName.PrincipalNameString() != b.SName.PrincipalNameString() {
		t.Errorf("AS-REQ: the proxy and TCP 88 refused differently\nproxy %+v\ntcp   %+v", a, b)
	}
	// And what they answered is what each should be: the AS-REQ asks for
	// pre-authentication, the TGS-REQ yields a ticket.
	var e messages.KRBError
	if err := e.Unmarshal(replyOf(t, postKKDCP(t, h, envelope(t, r.asReq, testRealm)))); err != nil || e.ErrorCode != 25 {
		t.Errorf("AS-REQ: want KDC_ERR_PREAUTH_REQUIRED (25), got %+v (%v)", e, err)
	}
	var rep messages.TGSRep
	if err := rep.Unmarshal(replyOf(t, postKKDCP(t, h, envelope(t, r.tgs, testRealm)))); err != nil {
		t.Errorf("TGS-REQ: not a TGS-REP: %v", err)
	}
}

func TestKKDCPRealmIsCaseInsensitive(t *testing.T) {
	r := newKKDCPRealm(t)
	replyOf(t, postKKDCP(t, r.s.KKDCPHandler(), envelope(t, r.asReq, strings.ToLower(testRealm))))
}

func TestKKDCPRefusals(t *testing.T) {
	r := newKKDCPRealm(t)
	h := r.s.KKDCPHandler()
	good := envelope(t, r.asReq, testRealm)

	// The same call that works, beside every refusal.
	if rec := postKKDCP(t, h, good); rec.Code != http.StatusOK {
		t.Fatalf("control: %d %s", rec.Code, rec.Body)
	}

	prefixed := func(prefix uint32, msg []byte) []byte {
		k := append(binary.BigEndian.AppendUint32(nil, prefix), msg...)
		b, err := asn1.Marshal(proxyMessage{KerbMessage: k, TargetDomain: testRealm})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	noRealm, err := asn1.Marshal(proxyMessage{KerbMessage: append(binary.BigEndian.AppendUint32(nil, uint32(len(r.asReq))), r.asReq...)})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		body []byte
		want int
	}{
		"empty body":               {nil, 400},
		"junk":                     {[]byte("GET / HTTP/1.1\r\n\r\n"), 400},
		"a bare Kerberos message":  {r.asReq, 400},
		"truncated":                {good[:len(good)-3], 400},
		"trailing bytes":           {append(append([]byte{}, good...), 0), 400},
		"no target-domain":         {noRealm, 400},
		"prefix too short":         {prefixed(uint32(len(r.asReq))-1, r.asReq), 400},
		"prefix too long":          {prefixed(uint32(len(r.asReq))+1, r.asReq), 400},
		"prefix with the high bit": {prefixed(0x8000_0000|uint32(len(r.asReq)), r.asReq), 400},
		"no prefix at all": {func() []byte {
			b, _ := asn1.Marshal(proxyMessage{KerbMessage: []byte{1, 2}, TargetDomain: testRealm})
			return b
		}(), 400},
		"a message that is no request": {envelope(t, []byte{0x30, 0x03, 0x02, 0x01, 0x05}, testRealm), 400},
		"another realm":                {envelope(t, r.asReq, "OTHER.TEST"), 403},
		"over the size bound":          {bytes.Repeat([]byte{0}, kkdcpMaxBody+1), 413},
	} {
		if rec := postKKDCP(t, h, tc.body); rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", name, rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/KdcProxy", bytes.NewReader(good)))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
			t.Errorf("%s: status %d, Allow %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

// FuzzKKDCP feeds arbitrary bodies to the handler: whatever arrives, nothing
// panics, the status is one the handler documents, and a 200 is a well-formed
// envelope around a KRB-ERROR or KDC-REP. Seeds: testdata/fuzz/FuzzKKDCP.
func FuzzKKDCP(f *testing.F) {
	r := newKKDCPRealm(f)
	h := r.s.KKDCPHandler()
	f.Add(envelope(f, r.asReq, testRealm))
	f.Add(envelope(f, r.tgs, testRealm))
	f.Add(envelope(f, r.asReq, "OTHER.TEST"))
	f.Add(envelope(f, []byte{0x6a, 0x03, 0x02, 0x01, 0x05}, testRealm))
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > kkdcpMaxBody {
			return
		}
		rec := postKKDCP(t, h, b)
		switch rec.Code {
		case 400, 403:
		case 200:
			out := replyOf(t, rec)
			var e messages.KRBError
			var a messages.ASRep
			var g messages.TGSRep
			if e.Unmarshal(out) != nil && a.Unmarshal(out) != nil && g.Unmarshal(out) != nil {
				t.Fatalf("a 200 that carries neither KRB-ERROR nor KDC-REP: %x", out)
			}
		default:
			t.Fatalf("status %d for %x", rec.Code, b)
		}
	})
}
