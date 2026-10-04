// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// tgsWith presents a TGT this realm sealed, valid from start to end, with a
// fresh authenticator, and asks for a service ticket lasting till.
func tgsWith(t *testing.T, s *Server, start, end, till time.Time, invalid bool) ([]byte, types.EncryptionKey) {
	t.Helper()
	return tgsWithETypes(t, s, start, end, till, invalid, []int32{defaultEtype})
}

// tgsWithETypes is tgsWith offering the given etypes.
func tgsWithETypes(t *testing.T, s *Server, start, end, till time.Time, invalid bool, etypes []int32) ([]byte, types.EncryptionKey) {
	t.Helper()
	tgtSName := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	client := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	fl := types.NewKrbFlags()
	if invalid {
		types.SetFlag(&fl, flags.Invalid)
	}
	tkt, sessionKey, err := messages.NewTicket(client, testRealm, tgtSName, testRealm,
		fl, s.cfg.Services, defaultEtype, 2, start, start, end, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	body := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		Till:  till, Nonce: 7, EType: etypes}
	return s.handle(signedTGSReq(t, tkt, sessionKey, client, body, bodyChecksum(t, sessionKey))), sessionKey
}

func krbErrorCode(t *testing.T, out []byte) int32 {
	t.Helper()
	var e messages.KRBError
	if err := e.Unmarshal(out); err != nil {
		var rep messages.TGSRep
		if rep.Unmarshal(out) == nil {
			t.Fatalf("a service ticket was issued (for %v), where a refusal was due", rep.Ticket.SName.NameString)
		}
		t.Fatalf("neither a KRB-ERROR nor a TGS-REP: %v", err)
	}
	return e.ErrorCode
}

// A TGT is a credential with an end, and the end is the whole of how a
// Kerberos credential is revoked: a password change or a removed person
// stops mattering only when the TGTs already handed out run out. A TGS
// that ignores the end hands out service tickets -- and fresh TGTs --
// for ever to whoever once held one.
func TestTGSRefusesATGTOutsideItsValidity(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	n := now().UTC()
	for _, c := range []struct {
		name       string
		start, end time.Time
		invalid    bool
		want       int32
	}{
		{"expired an hour ago", n.Add(-2 * time.Hour), n.Add(-time.Hour), false, errorcode.KRB_AP_ERR_TKT_EXPIRED},
		{"expired a second ago", n.Add(-time.Hour), n.Add(-time.Second), false, errorcode.KRB_AP_ERR_TKT_EXPIRED},
		{"not yet valid", n.Add(time.Hour), n.Add(2 * time.Hour), false, errorcode.KRB_AP_ERR_TKT_NYV},
		{"flagged invalid", n.Add(-time.Minute), n.Add(time.Hour), true, errorcode.KRB_AP_ERR_TKT_NYV},
	} {
		out, _ := tgsWith(t, s, c.start, c.end, n.Add(time.Hour), c.invalid)
		if got := krbErrorCode(t, out); got != c.want {
			t.Errorf("%s: error code %d, want %d", c.name, got, c.want)
		}
	}
}

// A service ticket bought with a TGT ends no later than the TGT, whatever
// the client asks for: otherwise renewing krbtgt through the TGS extends a
// credential indefinitely, one lifetime at a time.
func TestTGSTicketEndsWithItsTGT(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	n := now().UTC()
	tgtEnd := n.Add(10 * time.Minute).Truncate(time.Second)
	out, session := tgsWith(t, s, n.Add(-time.Minute), tgtEnd, n.Add(10*time.Hour), false)
	var rep messages.TGSRep
	if err := rep.Unmarshal(out); err != nil {
		t.Fatalf("a valid TGT was refused: %v (code %d)", err, krbErrorCode(t, out))
	}
	if err := rep.DecryptEncPart(session); err != nil {
		t.Fatal(err)
	}
	if end := rep.DecryptedEncPart.EndTime; end.After(tgtEnd) {
		t.Errorf("service ticket ends %v, after its TGT (%v)", end, tgtEnd)
	}
}

// A request without pre-authentication is answered without deriving the
// person's key: it costs the sender a small UDP packet from any address,
// and PBKDF2 costs the realm milliseconds. The key is derived only once a
// timestamp is there to check -- and a verifier-only person is still told
// NULL_KEY, not PREAUTH_REQUIRED.
func TestNoKeyIsDerivedForARequestWithoutPreauth(t *testing.T) {
	freshKeyCache(t)
	var n int
	orig := stringToKey
	stringToKey = func(p, s string, i int64, e etype.EType) ([]byte, error) { n++; return orig(p, s, i, e) }
	t.Cleanup(func() { stringToKey = orig })

	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	if got := errorCode(t, s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, nil))); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Fatalf("code %d, want PREAUTH_REQUIRED", got)
	}
	if n != 0 {
		t.Errorf("%d key derivations for a request without pre-authentication", n)
	}
	v := testServer(t, directory.NewIdentity("bob", directory.WithVerifier(func(string) error { return nil })))
	if got := errorCode(t, v.handle(asReq(t, "bob", []string{"krbtgt", testRealm}, nil))); got != errorcode.KDC_ERR_NULL_KEY {
		t.Errorf("a verifier-only person without preauth: code %d, want NULL_KEY", got)
	}
}
