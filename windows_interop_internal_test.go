// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"crypto/md5"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// windowsChecksum is the authenticator checksum a Windows client sends.
func windowsChecksum(b []byte) types.Checksum {
	sum := md5.Sum(b)
	return types.Checksum{CksumType: chksumtype.RSA_MD5, Checksum: sum[:]}
}

// go-authn/kdc#36, part 1. A Windows client (a workgroup Windows 11, injected
// with a TGT) signs the TGS-REQ authenticator with RSA-MD5, cksumtype 7:
// unkeyed, but inside the authenticator sealed under the TGT session key. MIT
// krb5 accepts it (kdc_util.c comp_cksum asks "collision-proof", not "keyed");
// see the doc comment of checkBodyChecksum for the argument and sources.
func TestWindowsRSAMD5AuthenticatorChecksum(t *testing.T) {
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
	md5Of := func(b []byte) types.Checksum {
		sum := md5.Sum(b)
		return types.Checksum{CksumType: chksumtype.RSA_MD5, Checksum: sum[:]}
	}
	honest := bodyChecksum(t, sk)

	for _, tc := range []struct {
		name  string
		cksum func([]byte) types.Checksum
		want  int32 // 0 = a service ticket
	}{
		{"Windows' form: RSA-MD5 over the body", md5Of, 0},
		{"the keyed checksum still verifies", honest, 0},
		{"RSA-MD5 over another body (a rewritten service)", func([]byte) types.Checksum {
			other := body("cifs")
			bb, err := other.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			return md5Of(bb)
		}, errorcode.KRB_AP_ERR_MODIFIED},
		{"RSA-MD5, one bit off", func(b []byte) types.Checksum {
			c := md5Of(b)
			c.Checksum[3] ^= 0x10
			return c
		}, errorcode.KRB_AP_ERR_MODIFIED},
		{"RSA-MD5 truncated", func(b []byte) types.Checksum {
			c := md5Of(b)
			c.Checksum = c.Checksum[:8]
			return c
		}, errorcode.KRB_AP_ERR_MODIFIED},
		{"RSA-MD5 empty", func([]byte) types.Checksum {
			return types.Checksum{CksumType: chksumtype.RSA_MD5}
		}, errorcode.KRB_AP_ERR_INAPP_CKSUM},
		{"RSA-MD4 stays refused", func(b []byte) types.Checksum {
			c := md5Of(b)
			c.CksumType = chksumtype.RSA_MD4
			return c
		}, errorcode.KRB_AP_ERR_INAPP_CKSUM},
		{"CRC32 stays refused", func(b []byte) types.Checksum {
			return types.Checksum{CksumType: chksumtype.CRC32, Checksum: []byte{1, 2, 3, 4}}
		}, errorcode.KRB_AP_ERR_INAPP_CKSUM},
		{"keyed checksum, one bit off", func(b []byte) types.Checksum {
			c := honest(b)
			c.Checksum[0] ^= 1
			return c
		}, errorcode.KRB_AP_ERR_MODIFIED},
	} {
		out := s.handle(signedTGSReq(t, tkt, sk, client, body("nfs"), tc.cksum))
		var rep messages.TGSRep
		if tc.want == 0 {
			if rep.Unmarshal(out) != nil {
				t.Errorf("%s: refused with error %d", tc.name, krbErrorCode(t, out))
			}
			continue
		}
		if got := krbErrorCode(t, out); got != tc.want {
			t.Errorf("%s: error %d, want %d", tc.name, got, tc.want)
		}
	}

	// A body tampered after Windows signed it: the signature is over the
	// original, the request carries another.
	signed := body("nfs")
	bb, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig := md5Of(bb)
	out := s.handle(signedTGSReq(t, tkt, sk, client, body("cifs"), func([]byte) types.Checksum { return sig }))
	if got := krbErrorCode(t, out); got != errorcode.KRB_AP_ERR_MODIFIED {
		t.Errorf("a body tampered after signing: error %d, want MODIFIED", got)
	}
}

// go-authn/kdc#36, part 2. RFC 4120 2.1, 3.1.3, 3.3.3 and MIT get_ticket_flags:
// an AS ticket is INITIAL and PRE-AUTHENT, a TGS ticket is not INITIAL, keeps
// PRE-AUTHENT and the TGT's authtime, and both carry a starttime -- in the
// ticket AND in the reply's encrypted part, which is what Windows reads.
func TestIssuedTicketsCarryFlagsAndStarttime(t *testing.T) {
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, id)
	key, err := s.cfg.keyFor(id)
	if err != nil {
		t.Fatal(err)
	}
	pa := timestampPA(t, key, now().UTC())
	out := s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, pa))
	var as messages.ASRep
	if err := as.Unmarshal(out); err != nil {
		t.Fatalf("AS-REQ refused: error %d", krbErrorCode(t, out))
	}
	plain, err := crypto.DecryptEncPart(as.EncPart, key, keyusage.AS_REP_ENCPART)
	if err != nil {
		t.Fatal(err)
	}
	var enc messages.EncKDCRepPart
	if err := enc.Unmarshal(plain); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		name string
		bit  int
	}{{"INITIAL", flags.Initial}, {"PRE-AUTHENT", flags.PreAuthent}} {
		if !types.IsFlagSet(&enc.Flags, f.bit) {
			t.Errorf("AS reply: %s not set", f.name)
		}
	}
	for _, f := range []struct {
		name string
		bit  int
	}{{"FORWARDABLE", flags.Forwardable}, {"RENEWABLE", flags.Renewable}, {"PROXIABLE", flags.Proxiable}, {"INVALID", flags.Invalid}} {
		if types.IsFlagSet(&enc.Flags, f.bit) {
			t.Errorf("AS reply: %s set though never granted", f.name)
		}
	}
	if enc.StartTime.IsZero() || enc.AuthTime.IsZero() || enc.StartTime.Before(enc.AuthTime) {
		t.Errorf("AS reply: starttime %v, authtime %v", enc.StartTime, enc.AuthTime)
	}

	// The ticket itself, decrypted with the krbtgt key.
	tgsKey, _, err := s.cfg.Services.GetEncryptionKey(types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}, testRealm, 0, defaultEtype)
	if err != nil {
		t.Fatal(err)
	}
	tkt := as.Ticket
	if err := tkt.Decrypt(tgsKey); err != nil {
		t.Fatal(err)
	}
	if !types.IsFlagSet(&tkt.DecryptedEncPart.Flags, flags.Initial) || !types.IsFlagSet(&tkt.DecryptedEncPart.Flags, flags.PreAuthent) {
		t.Errorf("the TGT's own flags lack INITIAL|PRE-AUTHENT: %v", tkt.DecryptedEncPart.Flags)
	}
	if tkt.DecryptedEncPart.StartTime.IsZero() {
		t.Error("the TGT carries no starttime")
	}

	// Buy a service ticket with that TGT, signed as Windows signs it.
	client := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	body := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		Till:  now().UTC().Add(time.Hour), Nonce: 9, EType: []int32{defaultEtype}}
	session := enc.Key
	tgsOut := s.handle(signedTGSReq(t, as.Ticket, session, client, body, bodyChecksum(t, session)))
	var tgs messages.TGSRep
	if err := tgs.Unmarshal(tgsOut); err != nil {
		t.Fatalf("TGS-REQ refused: error %d", krbErrorCode(t, tgsOut))
	}
	plain, err = crypto.DecryptEncPart(tgs.EncPart, session, keyusage.TGS_REP_ENCPART_SESSION_KEY)
	if err != nil {
		t.Fatal(err)
	}
	var te messages.EncKDCRepPart
	if err := te.Unmarshal(plain); err != nil {
		t.Fatal(err)
	}
	if types.IsFlagSet(&te.Flags, flags.Initial) {
		t.Error("TGS reply: INITIAL set (RFC 4120 3.3.3)")
	}
	if !types.IsFlagSet(&te.Flags, flags.PreAuthent) {
		t.Error("TGS reply: PRE-AUTHENT not inherited from the TGT")
	}
	if te.StartTime.IsZero() {
		t.Error("TGS reply: no starttime")
	}
	if !te.AuthTime.Equal(enc.AuthTime) {
		t.Errorf("TGS reply authtime %v, want the TGT's %v", te.AuthTime, enc.AuthTime)
	}
}
