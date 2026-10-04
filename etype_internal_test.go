package kdc

import (
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// RFC 4120 §3.1.3: a request whose etype list holds nothing this realm issues
// is answered KDC_ERR_ETYPE_NOSUPP. Before, the list was never read, and a
// client that offered only rc4 (23) or aes128 (17) was handed etype 18 anyway.
func TestARequestOfferingNoEtypeThisRealmIssuesIsRefused(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	for _, offered := range [][]int32{{23}, {17, 23}, {}} {
		as := s.handle(asReqETypes(t, "alice", []string{"krbtgt", testRealm}, nil, offered))
		if got := errorCode(t, as); got != errorcode.KDC_ERR_ETYPE_NOSUPP {
			t.Errorf("AS-REQ offering %v: code %d, want ETYPE_NOSUPP", offered, got)
		}
		// The same answer for somebody who does not exist: the etype is
		// checked before anybody is looked up.
		ghost := s.handle(asReqETypes(t, "nobody", []string{"krbtgt", testRealm}, nil, offered))
		if got := errorCode(t, ghost); got != errorcode.KDC_ERR_ETYPE_NOSUPP {
			t.Errorf("AS-REQ for nobody offering %v: code %d, want ETYPE_NOSUPP", offered, got)
		}
		n := now().UTC()
		tgs, _ := tgsWithETypes(t, s, n.Add(-time.Minute), n.Add(time.Hour), n.Add(time.Hour), false, offered)
		if got := krbErrorCode(t, tgs); got != errorcode.KDC_ERR_ETYPE_NOSUPP {
			t.Errorf("TGS-REQ offering %v: code %d, want ETYPE_NOSUPP", offered, got)
		}
	}
	// Etype 18 among others is fine.
	ok := s.handle(asReqETypes(t, "alice", []string{"krbtgt", testRealm}, nil, []int32{23, 18, 17}))
	if got := errorCode(t, ok); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Errorf("AS-REQ offering 23,18,17: code %d, want PREAUTH_REQUIRED", got)
	}
}

// The PREAUTH_REQUIRED hint names the etype AND the salt the key is derived
// with. It used to carry no salt at all.
func TestThePreauthHintNamesTheSalt(t *testing.T) {
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, id)
	var e messages.KRBError
	if err := e.Unmarshal(s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, nil))); err != nil {
		t.Fatal(err)
	}
	var pa types.PADataSequence
	if _, err := asn1.Unmarshal(e.EData, &pa); err != nil {
		t.Fatalf("e-data: %v", err)
	}
	for _, p := range pa {
		if p.PADataType != patype.PA_ETYPE_INFO2 {
			continue
		}
		var info types.ETypeInfo2
		if _, err := asn1.Unmarshal(p.PADataValue, &info); err != nil {
			t.Fatal(err)
		}
		if len(info) != 1 || info[0].EType != defaultEtype || info[0].Salt != testRealm+"alice" {
			t.Fatalf("ETYPE-INFO2 = %+v, want etype %d salt %q", info, defaultEtype, testRealm+"alice")
		}
		return
	}
	t.Fatal("no ETYPE-INFO2 in the PREAUTH_REQUIRED e-data")
}
