package kdc

import (
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// A ticket for a SERVICE, forged by whoever holds that service's key alone
// (here nfs/localhost, never the krbtgt key), presented to the TGS as if it
// were a TGT. The TGS looked the key up by the ticket's SName, which travels
// in the clear, so the forgery decrypted -- and bought a genuine krbtgt
// ticket for any name, "administrator" included, which the directory does
// not even hold. One service key was the realm's key. RFC 4120 3.3.2: a
// TGS-REQ carries a ticket-granting ticket.
func TestOnlyATicketGrantingTicketBuysTickets(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))

	// The attacker's keytab: only the NFS server's own key.
	nfsOnly := keytab.New()
	if err := nfsOnly.AddEntry("nfs/localhost", testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
		t.Fatal(err)
	}
	nfs := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}}
	victim := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"administrator"}}
	n := now().UTC()
	tkt, sk, err := messages.NewTicket(victim, testRealm, nfs, testRealm, types.NewKrbFlags(), nfsOnly,
		defaultEtype, 2, n.Add(-time.Minute), n.Add(-time.Minute), n.Add(10*time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	auth := types.Authenticator{AVNO: iana.PVNO, CRealm: testRealm, CName: victim, CTime: n, SeqNumber: 1}
	ab, err := auth.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	authED, err := crypto.GetEncryptedData(ab, sk, keyusage.AP_REQ_AUTHENTICATOR, 0) // gokrb5 picks usage 11 for a non-krbtgt ticket
	if err != nil {
		t.Fatal(err)
	}
	apb, err := (&messages.APReq{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REQ, APOptions: types.NewKrbFlags(),
		Ticket: tkt, EncryptedAuthenticator: authED}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	type marshalReq struct {
		PVNO    int                  `asn1:"explicit,tag:1"`
		MsgType int                  `asn1:"explicit,tag:2"`
		PAData  types.PADataSequence `asn1:"explicit,optional,tag:3"`
		ReqBody messages.KDCReqBody  `asn1:"explicit,tag:4"`
	}
	krbtgt := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	rb, _ := asn1.Marshal(marshalReq{PVNO: iana.PVNO, MsgType: msgtype.KRB_TGS_REQ,
		PAData:  types.PADataSequence{{PADataType: patype.PA_TGS_REQ, PADataValue: apb}},
		ReqBody: messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm, SName: krbtgt, Till: n.Add(10 * time.Hour), Nonce: 9, EType: []int32{18}}})
	out := s.handle(asn1tools.AddASNAppTag(rb, asnAppTag.TGSREQ))

	if got := krbErrorCode(t, out); got != errorcode.KRB_AP_ERR_NOT_US {
		t.Errorf("a forged service ticket at the TGS: error %d, want KRB_AP_ERR_NOT_US", got)
	}
}

// A person removed from the directory: their TGT, still valid, buys nothing.
func TestARemovedPersonsTGTBuysNothing(t *testing.T) {
	s := testServer(t, directory.NewIdentity("bob", directory.WithPassword("bobpw")))
	n := now().UTC()
	out, _ := tgsWith(t, s, n.Add(-time.Minute), n.Add(time.Hour), n.Add(time.Hour), false) // alice's TGT
	if got := krbErrorCode(t, out); got != errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN {
		t.Errorf("a TGT for someone the directory no longer holds: error %d, want KDC_ERR_C_PRINCIPAL_UNKNOWN", got)
	}
}

// freshKeyCache empties the derived-key cache for one test: it is global,
// and a key another test derived would hide a derivation this one counts.
func freshKeyCache(t *testing.T) {
	t.Helper()
	old := derived
	derived = &keyCache{m: map[[32]byte][]byte{}}
	t.Cleanup(func() { derived = old })
}

// A false or malformed PA-ENC-TIMESTAMP costs its sender a few bytes; it
// cost the realm a PBKDF2 each time (1.3 ms against 22 µs, measured with one
// byte of timestamp). The key is now derived once per password, however
// many attempts arrive, and again when the password changes.
func TestAFalseTimestampDoesNotCostAKeyDerivationEachTime(t *testing.T) {
	freshKeyCache(t)
	var n int
	orig := stringToKey
	stringToKey = func(p, s string, i int64, e etype.EType) ([]byte, error) { n++; return orig(p, s, i, e) }
	t.Cleanup(func() { stringToKey = orig })

	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	req := asReq(t, "alice", []string{"krbtgt", testRealm}, types.PADataSequence{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte{0}}})
	for range 200 {
		s.handle(req)
	}
	if n != 1 {
		t.Errorf("200 false timestamps: %d key derivations, want 1", n)
	}
	// A new password is a new key, not the old one served from memory.
	s2 := testServer(t, directory.NewIdentity("alice", directory.WithPassword("a new password")))
	s2.handle(req)
	if n != 2 {
		t.Errorf("after a password change: %d derivations in all, want 2", n)
	}
}
