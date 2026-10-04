package kdc

import (
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// signedTGSReq is a TGS-REQ as a client builds one: the body encoded once,
// the authenticator's checksum computed by cksum over those bytes, and the
// same bytes sent.
func signedTGSReq(t *testing.T, tkt messages.Ticket, sk types.EncryptionKey, client types.PrincipalName,
	body messages.KDCReqBody, cksum func([]byte) types.Checksum) []byte {
	t.Helper()
	bb, err := body.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	auth := types.Authenticator{AVNO: iana.PVNO, CRealm: testRealm, CName: client, CTime: now().UTC(), SeqNumber: 1}
	if cksum != nil {
		auth.Cksum = cksum(bb)
	}
	ab, err := auth.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	authED, err := crypto.GetEncryptedData(ab, sk, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR, 0)
	if err != nil {
		t.Fatal(err)
	}
	apb, err := (&messages.APReq{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REQ, APOptions: types.NewKrbFlags(),
		Ticket: tkt, EncryptedAuthenticator: authED}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req := messages.TGSReq{KDCReqFields: messages.KDCReqFields{PVNO: iana.PVNO, MsgType: msgtype.KRB_TGS_REQ,
		PAData:  types.PADataSequence{{PADataType: patype.PA_TGS_REQ, PADataValue: apb}},
		ReqBody: body}}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bodyChecksum is what an honest client puts in the authenticator: the
// session key's own keyed checksum, with key usage 6.
func bodyChecksum(t *testing.T, sk types.EncryptionKey) func([]byte) types.Checksum {
	return func(b []byte) types.Checksum {
		t.Helper()
		et, err := crypto.GetEtype(sk.KeyType)
		if err != nil {
			t.Fatal(err)
		}
		c, err := et.GetChecksumHash(sk.KeyValue, b, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
		if err != nil {
			t.Fatal(err)
		}
		return types.Checksum{CksumType: et.GetHashID(), Checksum: c}
	}
}

// ⛔ The authenticator binds the request. RFC 4120 3.3.2: its checksum is
// over the KDC-REQ-BODY, keyed by the session key -- otherwise anybody on the
// path rewrites the service, the lifetime or the nonce of a TGS-REQ in flight
// and the ticket is issued for what they wrote. Each request here differs
// from an honest one in its checksum alone.
func TestTheAuthenticatorMustBeAboutThisRequest(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	n := now().UTC()
	krbtgt := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	client := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	tkt, sk, err := messages.NewTicket(client, testRealm, krbtgt, testRealm, types.NewKrbFlags(), s.cfg.Services,
		defaultEtype, 2, n.Add(-time.Minute), n.Add(-time.Minute), n.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	body := func(service string) messages.KDCReqBody {
		return messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
			SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{service, "localhost"}},
			Till:  n.Add(time.Hour), Nonce: 7, EType: []int32{defaultEtype}}
	}
	honest := bodyChecksum(t, sk)

	// The control: the same request, honestly signed, is answered.
	var rep messages.TGSRep
	if out := s.handle(signedTGSReq(t, tkt, sk, client, body("nfs"), honest)); rep.Unmarshal(out) != nil {
		t.Fatalf("an honest TGS-REQ was refused: error %d", krbErrorCode(t, out))
	}

	for _, tc := range []struct {
		name  string
		cksum func([]byte) types.Checksum
		want  int32
	}{
		{"no checksum at all", nil, errorcode.KRB_AP_ERR_INAPP_CKSUM},
		{"an unkeyed CRC32", func([]byte) types.Checksum {
			return types.Checksum{CksumType: 1, Checksum: []byte{0xde, 0xad, 0xbe, 0xef}}
		}, errorcode.KRB_AP_ERR_INAPP_CKSUM},
		{"the right type over another body (a rewritten service)", func([]byte) types.Checksum {
			other := body("cifs")
			bb, err := other.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			return honest(bb)
		}, errorcode.KRB_AP_ERR_MODIFIED},
		{"the right type, one bit off", func(b []byte) types.Checksum {
			c := honest(b)
			c.Checksum[0] ^= 1
			return c
		}, errorcode.KRB_AP_ERR_MODIFIED},
	} {
		out := s.handle(signedTGSReq(t, tkt, sk, client, body("nfs"), tc.cksum))
		if got := krbErrorCode(t, out); got != tc.want {
			t.Errorf("%s: error %d, want %d", tc.name, got, tc.want)
		}
	}
}
