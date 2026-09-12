package kdc

import (
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// handle turns one request into one reply. An empty reply means nothing
// sensible can be said and the caller should drop the message: answering
// noise with a KRB-ERROR would make this a reflector.
func (s *Server) handle(req []byte) []byte {
	// The message type is the second field, but the cheapest way to tell an
	// AS-REQ from a TGS-REQ is to try each: they differ by an ASN.1
	// application tag, so a wrong guess fails to parse rather than producing
	// a plausible wrong structure.
	var as messages.ASReq
	if err := as.Unmarshal(req); err == nil {
		return s.serveAS(&as)
	}
	var tgs messages.TGSReq
	if err := tgs.Unmarshal(req); err == nil {
		return s.serveTGS(&tgs)
	}
	return nil
}

// krbErr renders a KRB-ERROR. A client reads the code and acts on it, so the
// code matters more than the text: KDC_ERR_PREAUTH_REQUIRED makes kinit ask
// for a password, and KDC_ERR_C_PRINCIPAL_UNKNOWN makes it give up.
func (s *Server) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

func (s *Server) krbErr(sname types.PrincipalName, code int32, text string, pa types.PADataSequence) []byte {
	s.logf("refused %s: %s (code %d)", principalName(sname), text, code)
	e := messages.NewKRBError(sname, s.cfg.Realm, code, text)
	if len(pa) > 0 {
		// The e-data of a PREAUTH_REQUIRED carries the pre-authentication
		// types the client may use, and the SALT for each. Without it a
		// client guesses the salt, and a guessed salt derives a key that
		// decrypts nothing — which looks exactly like a wrong password.
		b, err := asn1.Marshal(pa)
		if err == nil {
			e.EData = b
		}
	}
	b, err := e.Marshal()
	if err != nil {
		return nil
	}
	return b
}

// unknownPrincipal is the answer for a name this realm does not hold.
//
// It says so plainly rather than pretending the password was wrong. Hiding
// which names exist is a real consideration, but Kerberos gives the answer
// away anyway — a realm that returns PREAUTH_REQUIRED for everybody hands out
// an encrypted timestamp target for every guess, which is worse.
func (s *Server) unknownPrincipal(sname types.PrincipalName) []byte {
	return s.krbErr(sname, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "no such principal in this realm", nil)
}

// now is time.Now, replaceable so a test can put a clock where it needs one.
var now = time.Now
