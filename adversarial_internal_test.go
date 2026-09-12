package kdc

import (
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// What a real client will not send: a timestamp encrypted with the wrong key,
// one from an hour ago, one whose cipher is three bytes. MIT's kinit is the
// judge of what a realm does RIGHT; these are what it does when somebody is
// not kinit.

const testRealm = "FLEET.TEST"

func testServer(t *testing.T, id *directory.Identity) *Server {
	t.Helper()
	kt := keytab.New()
	for _, p := range []string{"krbtgt/" + testRealm, "nfs/localhost"} {
		if err := kt.AddEntry(p, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(Config{Realm: testRealm, People: onlyOne{id}, Services: kt, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type onlyOne struct{ id *directory.Identity }

func (o onlyOne) Identities() ([]*directory.Identity, error) {
	return []*directory.Identity{o.id}, nil
}
func (o onlyOne) Describe() string                 { return "one person" }
func (o onlyOne) Members(string) ([]string, error) { return nil, nil }

// asReq builds an AS-REQ with whatever pre-authentication is given.
func asReq(t *testing.T, cname string, sname []string, pa types.PADataSequence) []byte {
	t.Helper()
	body := messages.KDCReqBody{
		KDCOptions: types.NewKrbFlags(),
		CName:      types.PrincipalName{NameType: nametypePrincipal, NameString: []string{cname}},
		Realm:      testRealm,
		SName:      types.PrincipalName{NameType: nametypeSrvInst, NameString: sname},
		Till:       time.Now().Add(time.Hour).UTC(),
		Nonce:      42,
		EType:      []int32{defaultEtype},
	}
	type marshalReq struct {
		PVNO    int                  `asn1:"explicit,tag:1"`
		MsgType int                  `asn1:"explicit,tag:2"`
		PAData  types.PADataSequence `asn1:"explicit,optional,tag:3"`
		ReqBody messages.KDCReqBody  `asn1:"explicit,tag:4"`
	}
	b, err := asn1.Marshal(marshalReq{
		PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REQ, PAData: pa, ReqBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.ASREQ)
}

// timestampPA seals a PA-ENC-TIMESTAMP with a given key and time.
func timestampPA(t *testing.T, key types.EncryptionKey, when time.Time) types.PADataSequence {
	t.Helper()
	pt := types.PAEncTSEnc{
		PATimestamp: when,
		PAUSec:      int((when.UnixNano() / int64(time.Microsecond)) - (when.Unix() * 1e6)),
	}
	plain, err := asn1.Marshal(pt)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := crypto.GetEncryptedData(plain, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return types.PADataSequence{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: raw}}
}

// errorCode reads the code out of a KRB-ERROR reply.
func errorCode(t *testing.T, reply []byte) int32 {
	t.Helper()
	var e messages.KRBError
	if err := e.Unmarshal(reply); err != nil {
		t.Fatalf("the reply is not a KRB-ERROR: %v", err)
	}
	return e.ErrorCode
}

func TestPreauthRefusals(t *testing.T) {
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, id)
	good, err := s.cfg.keyFor(id)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := s.cfg.keyFor(directory.NewIdentity("alice", directory.WithPassword("not it")))
	if err != nil {
		t.Fatal(err)
	}
	tgt := []string{"krbtgt", testRealm}

	t.Run("a timestamp under the wrong key", func(t *testing.T) {
		// The one an attacker sends. It must not be told apart from a
		// malformed one by the CODE: both are PREAUTH_FAILED, and only this
		// side's log says which.
		got := errorCode(t, s.handle(asReq(t, "alice", tgt, timestampPA(t, wrong, time.Now()))))
		if got != 24 {
			t.Errorf("code = %d, want 24 (PREAUTH_FAILED)", got)
		}
	})

	t.Run("a timestamp from an hour ago", func(t *testing.T) {
		// The one that is nobody's fault. A client cannot tell it from a
		// wrong password without being told.
		got := errorCode(t, s.handle(asReq(t, "alice", tgt, timestampPA(t, good, time.Now().Add(-time.Hour)))))
		if got != 24 {
			t.Errorf("code = %d, want 24 (PREAUTH_FAILED)", got)
		}
	})

	t.Run("a three-byte cipher", func(t *testing.T) {
		// ⛔ gokrb5 panics on this. The check has to come before the
		// decryption, not after.
		ed := types.EncryptedData{EType: defaultEtype, KVNO: 1, Cipher: []byte{1, 2, 3}}
		raw, err := ed.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		pa := types.PADataSequence{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: raw}}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("a three-byte cipher PANICKED: %v", r)
			}
		}()
		if got := errorCode(t, s.handle(asReq(t, "alice", tgt, pa))); got != 24 {
			t.Errorf("code = %d, want 24 (PREAUTH_FAILED)", got)
		}
	})

	t.Run("pre-authentication that is not an EncryptedData", func(t *testing.T) {
		pa := types.PADataSequence{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte("hello")}}
		if got := errorCode(t, s.handle(asReq(t, "alice", tgt, pa))); got != 24 {
			t.Errorf("code = %d, want 24 (PREAUTH_FAILED)", got)
		}
	})

	t.Run("an unknown principal", func(t *testing.T) {
		if got := errorCode(t, s.handle(asReq(t, "mallory", tgt, timestampPA(t, good, time.Now())))); got != 6 {
			t.Errorf("code = %d, want 6 (C_PRINCIPAL_UNKNOWN)", got)
		}
	})

	t.Run("a service asked for straight from an AS-REQ", func(t *testing.T) {
		// Asking the AS for a service ticket skips the TGT entirely. This
		// realm does not offer it, and says which principal it will issue.
		got := errorCode(t, s.handle(asReq(t, "alice", []string{"nfs", "localhost"},
			timestampPA(t, good, time.Now()))))
		if got != 7 {
			t.Errorf("code = %d, want 7 (S_PRINCIPAL_UNKNOWN)", got)
		}
	})

	t.Run("a principal with two components", func(t *testing.T) {
		// A service asking for a TGT of its own. Services authenticate from
		// a keytab, not from a directory of people.
		req := asReq(t, "alice", tgt, timestampPA(t, good, time.Now()))
		_ = req
		if _, err := s.lookup(types.PrincipalName{NameString: []string{"nfs", "localhost"}}); err != ErrNotAPerson {
			t.Errorf("err = %v, want ErrNotAPerson", err)
		}
	})
}

func TestAVerifierCannotBackARealm(t *testing.T) {
	// The structural limit, as a unit test as well as through kinit: a KDC
	// must DECRYPT with the person's key, and a verifier does not produce one.
	s := testServer(t, directory.NewIdentity("alice",
		directory.WithVerifier(func(string) error { return nil })))
	got := errorCode(t, s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, nil)))
	if got != 9 {
		t.Errorf("code = %d, want 9 (NULL_KEY)", got)
	}
}

func TestNoiseIsNotAnswered(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("x")))
	for _, junk := range [][]byte{nil, []byte("hello"), {0x6a, 0x00}, make([]byte, 64)} {
		if out := s.handle(junk); len(out) != 0 {
			t.Errorf("%x was answered with %d bytes", junk, len(out))
		}
	}
}

func TestZeroValuesResolve(t *testing.T) {
	c := Config{}
	if c.lifetime() != 10*time.Hour {
		t.Errorf("lifetime = %v", c.lifetime())
	}
	if c.skew() != 5*time.Minute {
		t.Errorf("skew = %v", c.skew())
	}
	set := Config{Lifetime: time.Hour, MaxSkew: time.Minute}
	if set.lifetime() != time.Hour || set.skew() != time.Minute {
		t.Errorf("a realm that set them did not keep them: %v %v", set.lifetime(), set.skew())
	}
}
