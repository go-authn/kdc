// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// go-authn/kdc#39. RFC 4120 3.2.3: the client name and realm of the ticket are
// compared with the authenticator's, KRB_AP_ERR_BADMATCH when they differ (MIT
// rd_req_dec.c does it with krb5_principal_compare). The TGS read neither.
func TestTheAuthenticatorMustNameTheTicketsClient(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	n := now().UTC()
	krbtgt := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	alice := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	tkt, sk, err := messages.NewTicket(alice, testRealm, krbtgt, testRealm, types.NewKrbFlags(), s.cfg.Services,
		defaultEtype, 2, n.Add(-time.Minute), n.Add(-time.Minute), n.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	body := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		Till:  n.Add(time.Hour), Nonce: 7, EType: []int32{defaultEtype}}
	ck := bodyChecksum(t, sk)
	name := func(parts ...string) types.PrincipalName {
		return types.PrincipalName{NameType: nametypePrincipal, NameString: parts}
	}

	for _, tc := range []struct {
		name  string
		cname types.PrincipalName
		realm string
		want  int32 // 0: a ticket is issued
	}{
		{"the control: the same client", alice, testRealm, 0},
		{"the name type is not compared (MIT does not)", types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"alice"}}, testRealm, 0},
		{"another person", name("bob"), testRealm, errorcode.KRB_AP_ERR_BADMATCH},
		{"another realm", alice, "OTHER.TEST", errorcode.KRB_AP_ERR_BADMATCH},
		{"a longer name", name("alice", "admin"), testRealm, errorcode.KRB_AP_ERR_BADMATCH},
		{"an empty name", name(), testRealm, errorcode.KRB_AP_ERR_BADMATCH},
		{"a case change", name("Alice"), testRealm, errorcode.KRB_AP_ERR_BADMATCH},
	} {
		out := s.handle(signedTGSReqAs(t, tkt, sk, tc.cname, tc.realm, body, ck))
		if tc.want == 0 {
			var rep messages.TGSRep
			if rep.Unmarshal(out) != nil {
				t.Errorf("%s: refused with error %d", tc.name, krbErrorCode(t, out))
			}
			continue
		}
		if got := krbErrorCode(t, out); got != tc.want {
			t.Errorf("%s: error %d, want %d", tc.name, got, tc.want)
		}
	}
}
