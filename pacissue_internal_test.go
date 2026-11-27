// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"errors"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc/internal/pac"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const testDomainSID = "S-1-5-21-1111111111-2222222222-3333333333"

type peopleList []*directory.Identity

func (m peopleList) Identities() ([]*directory.Identity, error) { return m, nil }
func (m peopleList) Describe() string                           { return "some people" }
func (m peopleList) Members(string) ([]string, error)           { return nil, nil }

func person(t *testing.T, name, uid, gid string, groups ...string) *directory.Identity {
	t.Helper()
	at := []directory.Attribute{}
	if uid != "" {
		at = append(at, directory.Attribute{Name: "uidNumber", Values: []string{uid}})
	}
	if gid != "" {
		at = append(at, directory.Attribute{Name: "gidNumber", Values: []string{gid}})
	}
	a, err := directory.NewAttributes(at...)
	if err != nil {
		t.Fatal(err)
	}
	return directory.NewIdentity(name, directory.WithPassword(name+"pw"), directory.WithAttributes(a), directory.WithGroups(groups...))
}

func pacServer(t *testing.T, people peopleList, p *PAC) (*Server, *keytab.Keytab) {
	t.Helper()
	kt := keytab.New()
	for _, n := range []string{"krbtgt/" + testRealm, "nfs/localhost", "http/other"} {
		if err := kt.AddEntry(n, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(Config{Realm: testRealm, People: people, Services: kt, Logf: t.Logf, AllowPasswordDerivedAS: true, PAC: p})
	if err != nil {
		t.Fatal(err)
	}
	return s, kt
}

func nfsTicket(t *testing.T, s *Server, kt *keytab.Keytab) (messages.Ticket, []byte) {
	t.Helper()
	n := now().UTC()
	out, _ := tgsWith(t, s, n.Add(-time.Minute), n.Add(time.Hour), n.Add(time.Hour), false)
	var rep messages.TGSRep
	if err := rep.Unmarshal(out); err != nil {
		t.Fatalf("no ticket (error %d): %v", krbErrorCode(t, out), err)
	}
	key, _, err := kt.GetEncryptionKey(rep.Ticket.SName, testRealm, 0, defaultEtype)
	if err != nil {
		t.Fatal(err)
	}
	if err := rep.Ticket.Decrypt(key); err != nil {
		t.Fatal(err)
	}
	return rep.Ticket, key.KeyValue
}

// pacOf extracts the PAC bytes from a decrypted ticket, and the EncTicketPart
// as it is signed (the PAC replaced by one zero byte).
func pacOf(t *testing.T, tkt messages.Ticket) (pacBytes, zeroed []byte) {
	t.Helper()
	ad := tkt.DecryptedEncPart.AuthorizationData
	if len(ad) != 1 || ad[0].ADType != adtype.ADIfRelevant {
		t.Fatalf("authorization data %v", ad)
	}
	var inner types.AuthorizationData
	if _, err := asn1.Unmarshal(ad[0].ADData, &inner); err != nil || len(inner) != 1 || inner[0].ADType != adtype.ADWin2KPAC {
		t.Fatalf("inner %v %v", inner, err)
	}
	etp := tkt.DecryptedEncPart
	z, err := asn1.Marshal(types.AuthorizationData{{ADType: adtype.ADWin2KPAC, ADData: []byte{0}}})
	if err != nil {
		t.Fatal(err)
	}
	etp.AuthorizationData = types.AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: z}}
	b, err := asn1.Marshal(etp)
	if err != nil {
		t.Fatal(err)
	}
	return inner[0].ADData, asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart)
}

func TestAServiceThatWantsAPACGetsOneThatVerifies(t *testing.T) {
	alice := person(t, "alice", "1001", "1000", "staff", "nogid")
	s, kt := pacServer(t, peopleList{alice, person(t, "bob", "1002", "1000")}, &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}})
	tkt, svcKey := nfsTicket(t, s, kt)
	pb, zeroed := pacOf(t, tkt)
	p, err := pac.Parse(pb)
	if err != nil {
		t.Fatal(err)
	}
	krbtgt, _, _ := kt.GetEncryptionKey(types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}, testRealm, 0, defaultEtype)
	svc := types.EncryptionKey{KeyType: defaultEtype, KeyValue: svcKey}
	if err := p.Verify(svc, krbtgt, true, zeroed); err != nil {
		t.Fatalf("the PAC does not verify: %v", err)
	}
	at, name, err := p.ClientInfo()
	if err != nil || name != "alice" {
		t.Fatalf("client %q %v", name, err)
	}
	if want := tkt.DecryptedEncPart.AuthTime.Unix(); at != want {
		t.Errorf("CLIENT_INFO authtime %d, ticket %d", at, want)
	}
	if tkt.DecryptedEncPart.AuthTime.Nanosecond() != 0 {
		t.Errorf("the ticket's authtime has sub-second parts")
	}
	b, _ := p.Buffer(pac.TypeLogonInfo)
	li, err := pac.UnmarshalLogonInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	if li.UserID != 1001 || li.PrimaryGroupID != 1000 || li.LogonDomainID.String() != testDomainSID {
		t.Errorf("logon info %+v", li)
	}
	if len(li.Groups) != 1 || li.Groups[0].RID != 1000 {
		t.Errorf("a group without a gidNumber is omitted, one with is kept: %+v", li.Groups)
	}
	// The wrong server key refuses it: the signature is the service's.
	other := types.EncryptionKey{KeyType: defaultEtype, KeyValue: make([]byte, 32)}
	if p.Verify(other, krbtgt, true, zeroed) == nil {
		t.Error("a PAC verified under a key that did not sign it")
	}
}

// The D bit (LOGON_EXTRA_SIDS, [MS-PAC] 2.5) is set only with ExtraSids, and a
// service ticket carries neither buffer 17 nor 18 (TGT-only, [MS-KILE]
// 3.3.5.6.4.7-8).
func TestServiceTicketPACHasNoDBitWithoutExtraSidsAndNoTGTBuffers(t *testing.T) {
	s, kt := pacServer(t, peopleList{person(t, "alice", "1001", "1000")}, &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}})
	tkt, _ := nfsTicket(t, s, kt)
	pb, _ := pacOf(t, tkt)
	p, err := pac.Parse(pb)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.Buffer(pac.TypeLogonInfo)
	li, err := pac.UnmarshalLogonInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(li.ExtraSIDs) == 0 && li.UserFlags&0x20 != 0 {
		t.Errorf("D bit set (UserFlags %#x) with no ExtraSids", li.UserFlags)
	}
	for _, typ := range []uint32{pac.TypeAttributesInfo, pac.TypeRequestorSID} {
		if _, ok := p.Buffer(typ); ok {
			t.Errorf("a service ticket PAC carries buffer %d", typ)
		}
	}
}

func TestAServiceNotListedGetsNoPAC(t *testing.T) {
	for name, p := range map[string]*PAC{"default": nil, "other service": {DomainSID: testDomainSID, Services: []string{"http/other"}}} {
		s, kt := pacServer(t, peopleList{person(t, "alice", "1001", "1000")}, p)
		tkt, _ := nfsTicket(t, s, kt)
		if len(tkt.DecryptedEncPart.AuthorizationData) != 0 {
			t.Errorf("%s: a ticket with authorization data: %v", name, tkt.DecryptedEncPart.AuthorizationData)
		}
	}
}

func TestAPACServiceRefusesWhatCannotBeGivenASoundPAC(t *testing.T) {
	cfg := &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}}
	for name, people := range map[string]peopleList{
		"no uidNumber":    {person(t, "alice", "", "1000")},
		"uidNumber twice": {person(t, "alice", "1001", "1000"), person(t, "mallory", "1001", "1000")},
		"not a number":    {person(t, "alice", "abc", "1000")},
	} {
		s, _ := pacServer(t, people, cfg)
		n := now().UTC()
		out, _ := tgsWith(t, s, n.Add(-time.Minute), n.Add(time.Hour), n.Add(time.Hour), false)
		if got := krbErrorCode(t, out); got != errorcode.KDC_ERR_POLICY {
			t.Errorf("%s: error %d, want KDC_ERR_POLICY", name, got)
		}
	}
}

func TestPACConfigIsChecked(t *testing.T) {
	kt := keytab.New()
	if err := kt.AddEntry("krbtgt/"+testRealm, testRealm, "x", time.Now(), 2, 18); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"", "S-1-5-21-1-2-3-4", "S-1-5-32-544", "S-1-4-21-1-2-3", "nonsense"} {
		_, err := New(Config{Realm: testRealm, People: peopleList{}, Services: kt, PAC: &PAC{DomainSID: sid}})
		if !errors.Is(err, ErrBadDomainSID) {
			t.Errorf("%q: %v", sid, err)
		}
	}
	sid, err := NewDomainSID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Realm: testRealm, People: peopleList{}, Services: kt, PAC: &PAC{DomainSID: sid}}); err != nil {
		t.Errorf("a generated SID %q: %v", sid, err)
	}
}
