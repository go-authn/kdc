// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc/internal/cammac"
	"github.com/go-authn/kdc/internal/pac"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// D7 (docs/design/pac-d7.md): the TGT's signed marking, and what the PAC
// makes of it.

const mintedSID = testDomainSID + "-1073741824" // DefaultMintedRID = 1<<30

var (
	tgtSName   = types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	aliceName  = types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	nfsSName   = []string{"nfs", "localhost"}
	krbtgtName = []string{"krbtgt", testRealm}
)

// d7Server is a PAC realm with alice (1001) and minting on.
func d7Server(t *testing.T, d directory.Source, p *PAC) (*Server, *keytab.Keytab) {
	t.Helper()
	kt := testKeytab(t)
	if p == nil {
		p = &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}}
	}
	s, err := New(Config{Realm: testRealm, People: d, Services: kt, Logf: t.Logf, AllowPasswordDerivedAS: true, PAC: p,
		MintCallers: []string{"https://login.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	return s, kt
}

func aliceDir(t *testing.T) *dirPeople {
	return &dirPeople{ids: []*directory.Identity{person(t, "alice", "1001", "1000")}}
}

func krbtgtKey(t *testing.T, kt *keytab.Keytab) (types.EncryptionKey, int) {
	t.Helper()
	k, kvno, err := kt.GetEncryptionKey(tgtSName, testRealm, 0, defaultEtype)
	if err != nil {
		t.Fatal(err)
	}
	return k, kvno
}

// asTGT is a password logon.
func asTGT(t *testing.T, s *Server) (messages.Ticket, types.EncryptionKey) {
	t.Helper()
	id, err := s.lookup(aliceName)
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.cfg.keyFor(id)
	if err != nil {
		t.Fatal(err)
	}
	out := s.handle(asReq(t, "alice", krbtgtName, timestampPA(t, key, now().UTC())))
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
	return as.Ticket, enc.Key
}

// mintedTGT is a bridge logon.
func mintedTGT(t *testing.T, s *Server, method string) (messages.Ticket, types.EncryptionKey) {
	t.Helper()
	raw, err := s.Mint(MintRequest{Principal: "alice", Method: method})
	if err != nil {
		t.Fatal(err)
	}
	var cred messages.KRBCred
	if err := cred.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	var part messages.EncKrbCredPart
	if err := part.Unmarshal(cred.EncPart.Cipher); err != nil {
		t.Fatal(err)
	}
	return cred.Tickets[0], part.TicketInfo[0].Key
}

// open decrypts a TGT of ours.
func open(t *testing.T, kt *keytab.Keytab, tkt messages.Ticket) (messages.EncTicketPart, int) {
	t.Helper()
	k, _ := krbtgtKey(t, kt)
	if err := tkt.Decrypt(k); err != nil {
		t.Fatal(err)
	}
	return tkt.DecryptedEncPart, tkt.EncPart.KVNO
}

func claimsOf(t *testing.T, kt *keytab.Keytab, tkt messages.Ticket) cammac.Claims {
	t.Helper()
	etp, kvno := open(t, kt, tkt)
	k, _ := krbtgtKey(t, kt)
	c, found, err := cammac.Find(etp, k, kvno)
	if err != nil || !found {
		t.Fatalf("no verifying marking: found=%v err=%v", found, err)
	}
	return c
}

func buy(t *testing.T, s *Server, tkt messages.Ticket, sk types.EncryptionKey, sname []string, extra func(*messages.KDCReqBody)) []byte {
	t.Helper()
	body := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: sname},
		Till:  now().UTC().Add(time.Hour), Nonce: 11, EType: []int32{defaultEtype}}
	if extra != nil {
		extra(&body)
	}
	return s.handle(signedTGSReq(t, tkt, sk, aliceName, body, bodyChecksum(t, sk)))
}

func extraSIDs(li *pac.LogonInfo) []string {
	var out []string
	for _, e := range li.ExtraSIDs {
		out = append(out, e.SID.String())
	}
	return out
}

func wantLogon(t *testing.T, what string, out []byte, kt *keytab.Keytab, sids ...string) {
	t.Helper()
	li := logonOf(t, out, kt)
	if got := extraSIDs(li); !slices.Equal(got, sids) {
		t.Errorf("%s: ExtraSids %v, want %v", what, got, sids)
	}
	if li.UserFlags&0x20 == 0 {
		t.Errorf("%s: ExtraSids without the D bit (UserFlags %#x)", what, li.UserFlags)
	}
	for _, e := range li.ExtraSIDs {
		if e.Attrs != pac.GroupAttrs {
			t.Errorf("%s: attributes %#x", what, e.Attrs)
		}
		if e.SID.String() == "S-1-18-2" {
			t.Errorf("%s: S-1-18-2 (service asserted identity) is never ours to write", what)
		}
	}
}

func TestAPasswordTGTIsMarkedAndItsPACSaysAuthorityAsserted(t *testing.T) {
	s, kt := d7Server(t, aliceDir(t), nil)
	tkt, sk := asTGT(t, s)
	if c := claimsOf(t, kt, tkt); c.Minted() || c.UID != 1001 {
		t.Fatalf("password TGT marking %+v", c)
	}
	wantLogon(t, "password", buy(t, s, tkt, sk, nfsSName, nil), kt, "S-1-18-1")
}

func TestAMintedTGTSaysHowAndItsPACCarriesTheMintedSID(t *testing.T) {
	for _, m := range []string{"passkey", "federated", "machine"} {
		s, kt := d7Server(t, aliceDir(t), nil)
		tkt, sk := mintedTGT(t, s, m)
		c := claimsOf(t, kt, tkt)
		if !c.Minted() || c.UID != 1001 || c.Methods[0] != "bridge-"+m {
			t.Fatalf("%s: marking %+v", m, c)
		}
		wantLogon(t, m, buy(t, s, tkt, sk, nfsSName, nil), kt, "S-1-18-1", mintedSID)
	}
}

func TestTheTGSCarriesTheMarkingIntoTheTGTItReissues(t *testing.T) {
	s, kt := d7Server(t, aliceDir(t), nil)
	for name, get := range map[string]func() (messages.Ticket, types.EncryptionKey){
		"minted":   func() (messages.Ticket, types.EncryptionKey) { return mintedTGT(t, s, "passkey") },
		"password": func() (messages.Ticket, types.EncryptionKey) { return asTGT(t, s) },
	} {
		tkt, sk := get()
		want := claimsOf(t, kt, tkt)
		out := buy(t, s, tkt, sk, krbtgtName, nil)
		var rep messages.TGSRep
		if err := rep.Unmarshal(out); err != nil {
			t.Fatalf("%s: krbtgt refused: error %d", name, krbErrorCode(t, out))
		}
		if err := rep.DecryptEncPart(sk); err != nil {
			t.Fatal(err)
		}
		again := claimsOf(t, kt, rep.Ticket)
		if fmt.Sprint(again) != fmt.Sprint(want) {
			t.Errorf("%s: reissued marking %+v, was %+v", name, again, want)
		}
		// And the reissued TGT buys the same PAC.
		sids := []string{"S-1-18-1"}
		if want.Minted() {
			sids = append(sids, mintedSID)
		}
		wantLogon(t, name+" reissued", buy(t, s, rep.Ticket, rep.DecryptedEncPart.Key, nfsSName, nil), kt, sids...)
	}
}

// craft seals a TGT for alice under the REAL krbtgt key with whatever
// authorization data ad makes of the ticket.
func craft(t *testing.T, kt *keytab.Keytab, ad func(messages.EncTicketPart) types.AuthorizationData) (messages.Ticket, types.EncryptionKey) {
	t.Helper()
	et, _ := crypto.GetEtype(defaultEtype)
	session, err := types.GenerateEncryptionKey(et)
	if err != nil {
		t.Fatal(err)
	}
	n := now().UTC().Truncate(time.Second)
	etp := messages.EncTicketPart{Flags: types.NewKrbFlags(), Key: session, CRealm: testRealm, CName: aliceName,
		AuthTime: n, StartTime: n, EndTime: n.Add(time.Hour)}
	if ad != nil {
		etp.AuthorizationData = ad(etp)
	}
	b, err := asn1.Marshal(etp)
	if err != nil {
		t.Fatal(err)
	}
	k, kvno := krbtgtKey(t, kt)
	ed, err := crypto.GetEncryptedData(asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart), k, keyusage.KDC_REP_TICKET, kvno)
	if err != nil {
		t.Fatal(err)
	}
	return messages.Ticket{TktVNO: 5, Realm: testRealm, SName: tgtSName, EncPart: ed}, session
}

// cammacOf pulls the container bytes out of authorization data.
func cammacOf(t *testing.T, ad types.AuthorizationData) []byte {
	t.Helper()
	var in types.AuthorizationData
	if _, err := asn1.Unmarshal(ad[0].ADData, &in); err != nil {
		t.Fatal(err)
	}
	return in[0].ADData
}

func wrap(t *testing.T, container []byte) types.AuthorizationData {
	t.Helper()
	in, err := asn1.Marshal(types.AuthorizationData{{ADType: cammac.ADCAMMAC, ADData: container}})
	if err != nil {
		t.Fatal(err)
	}
	return types.AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: in}}
}

func TestAForgedOrUnsignedMarkingIsRefused(t *testing.T) {
	s, kt := d7Server(t, aliceDir(t), nil)
	realKey, kvno := krbtgtKey(t, kt)
	minted := cammac.Claims{Methods: []string{cammac.MethodMachine}, UID: 1001}
	otherKey := realKey
	otherKey.KeyValue = bytes.Repeat([]byte{9}, len(realKey.KeyValue))

	sealed := func(k types.EncryptionKey) func(messages.EncTicketPart) types.AuthorizationData {
		return func(etp messages.EncTicketPart) types.AuthorizationData {
			ad, err := cammac.Seal(etp, minted, k, kvno)
			if err != nil {
				t.Fatal(err)
			}
			return ad
		}
	}
	cases := map[string]func(messages.EncTicketPart) types.AuthorizationData{
		"a container sealed with another key": sealed(otherKey),
		"an unsigned container": func(etp messages.EncTicketPart) types.AuthorizationData {
			els := types.AuthorizationData{{ADType: cammac.ADRequestorUID, ADData: []byte{0x02, 0x02, 0x03, 0xe9}}}
			cb, err := asn1.Marshal(struct {
				Elements types.AuthorizationData `asn1:"explicit,tag:0"`
			}{els})
			if err != nil {
				t.Fatal(err)
			}
			return wrap(t, cb)
		},
		"a verifier copied from another ticket": func(etp messages.EncTicketPart) types.AuthorizationData {
			other := etp
			other.CName = types.PrincipalName{NameType: 1, NameString: []string{"bob"}}
			ad, err := cammac.Seal(other, minted, realKey, kvno)
			if err != nil {
				t.Fatal(err)
			}
			return ad
		},
		"a verifier that names another key version": func(etp messages.EncTicketPart) types.AuthorizationData {
			ad, err := cammac.Seal(etp, minted, realKey, kvno+1)
			if err != nil {
				t.Fatal(err)
			}
			return ad
		},
		"garbage in the container": func(etp messages.EncTicketPart) types.AuthorizationData {
			return wrap(t, []byte{0x30, 0x03, 0x01, 0x01, 0xff})
		},
	}
	// Every flipped byte of a good container.
	good := sealed(realKey)
	{
		tkt, _ := craft(t, kt, good)
		etp, _ := open(t, kt, tkt)
		raw := cammacOf(t, etp.AuthorizationData)
		for i := range raw {
			cases[fmt.Sprintf("byte %d flipped", i)] = func(etp messages.EncTicketPart) types.AuthorizationData {
				m := bytes.Clone(raw)
				m[i] ^= 0x01
				return wrap(t, m)
			}
		}
	}
	for name, ad := range cases {
		tkt, sk := craft(t, kt, ad)
		out := buy(t, s, tkt, sk, nfsSName, nil)
		code := krbErrorCode(t, out)
		if code != errorcode.KRB_AP_ERR_MODIFIED {
			t.Errorf("%s: error %d, want KRB_AP_ERR_MODIFIED", name, code)
		}
	}
	// The control: the same ticket, sealed right, is accepted, and a bridge's.
	tkt, sk := craft(t, kt, good)
	wantLogon(t, "control", buy(t, s, tkt, sk, nfsSName, nil), kt, "S-1-18-1", mintedSID)
}

func TestTheClientsOwnAuthorizationDataIsNotAMarking(t *testing.T) {
	s, kt := d7Server(t, aliceDir(t), nil)
	tkt, sk := asTGT(t, s)
	// A password TGT; the request's enc-authorization-data claims a bridge login,
	// under the session key (so it decrypts: it is as valid as a client can make it).
	k, kvno := krbtgtKey(t, kt)
	etp, _ := open(t, kt, tkt)
	ad, err := cammac.Seal(etp, cammac.Claims{Methods: []string{cammac.MethodPasskey}, UID: 1001}, k, kvno)
	if err != nil {
		t.Fatal(err)
	}
	b, err := asn1.Marshal(ad)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := crypto.GetEncryptedData(b, sk, keyusage.TGS_REQ_KDC_REQ_BODY_AUTHDATA_SESSION_KEY, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := buy(t, s, tkt, sk, nfsSName, func(b *messages.KDCReqBody) { b.EncAuthData = ed })
	wantLogon(t, "client-supplied marking", out, kt, "S-1-18-1")
}

func TestARecreatedAccountsTGTBuysNothing(t *testing.T) {
	d := aliceDir(t)
	s, kt := d7Server(t, d, nil)
	for name, get := range map[string]func() (messages.Ticket, types.EncryptionKey){
		"password": func() (messages.Ticket, types.EncryptionKey) { return asTGT(t, s) },
		"minted":   func() (messages.Ticket, types.EncryptionKey) { return mintedTGT(t, s, "passkey") },
	} {
		d.ids = []*directory.Identity{person(t, "alice", "1001", "1000")}
		tkt, sk := get()
		if c := krbErrorCode2(t, buy(t, s, tkt, sk, nfsSName, nil)); c != 0 {
			t.Fatalf("%s: the control was refused: %d", name, c)
		}
		// alice deleted, a NEW alice created with another uidNumber.
		d.ids = []*directory.Identity{person(t, "alice", "2002", "1000")}
		for what, sname := range map[string][]string{"service": nfsSName, "krbtgt": krbtgtName} {
			if got := krbErrorCode(t, buy(t, s, tkt, sk, sname, nil)); got != errorcode.KDC_ERR_TGT_REVOKED {
				t.Errorf("%s/%s: error %d, want KDC_ERR_TGT_REVOKED", name, what, got)
			}
		}
		// A uidNumber taken away is the same.
		d.ids = []*directory.Identity{person(t, "alice", "", "1000")}
		if got := krbErrorCode(t, buy(t, s, tkt, sk, nfsSName, nil)); got != errorcode.KDC_ERR_TGT_REVOKED {
			t.Errorf("%s: uidNumber removed: error %d", name, got)
		}
	}
	_ = kt
}

// unmarkedTGT is what v0.12 issued: no container.
func unmarkedTGT(t *testing.T, s *Server, start time.Time) (messages.Ticket, types.EncryptionKey) {
	t.Helper()
	n := now().UTC()
	tkt, sk, err := messages.NewTicket(aliceName, testRealm, tgtSName, testRealm, types.NewKrbFlags(), s.cfg.Services,
		defaultEtype, 2, start, start, n.Add(48*time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return tkt, sk
}

func TestUnmarkedTGTsAreAcceptedForTenHoursAfterTheUpgrade(t *testing.T) {
	s, kt := d7Server(t, aliceDir(t), nil)
	old := s.started.Add(-time.Hour)

	tkt, sk := unmarkedTGT(t, s, old)
	wantLogon(t, "unmarked, inside the window", buy(t, s, tkt, sk, nfsSName, nil), kt, "S-1-18-1") // a password logon

	// An unmarked TGT that STARTS after the server did was not issued by the
	// version before: nothing that old can have it.
	late, lsk := unmarkedTGT(t, s, s.started.Add(time.Second))
	orig := now
	t.Cleanup(func() { now = orig })
	now = func() time.Time { return orig().Add(time.Minute) }
	if got := krbErrorCode(t, buy(t, s, late, lsk, nfsSName, nil)); got != errorcode.KDC_ERR_TGT_REVOKED {
		t.Errorf("an unmarked TGT started after the server: error %d", got)
	}

	// Nine hours later: still accepted. Past ten: refused.
	now = func() time.Time { return s.started.Add(9 * time.Hour) }
	tkt, sk = unmarkedTGT(t, s, old)
	if c := krbErrorCode2(t, buy(t, s, tkt, sk, nfsSName, nil)); c != 0 {
		t.Errorf("an unmarked TGT at 9 h: error %d", c)
	}
	now = func() time.Time { return s.started.Add(MaxUnmarkedWindow + time.Second) }
	tkt, sk = unmarkedTGT(t, s, old)
	if got := krbErrorCode(t, buy(t, s, tkt, sk, nfsSName, nil)); got != errorcode.KDC_ERR_TGT_REVOKED {
		t.Errorf("an unmarked TGT after the window: error %d", got)
	}
}

func TestTheUnmarkedWindowIsConfigurable(t *testing.T) {
	now0 := now
	t.Cleanup(func() { now = now0 })
	for name, p := range map[string]*PAC{
		"refuse at once":  {DomainSID: testDomainSID, Services: []string{"nfs/localhost"}, RefuseUnmarked: true},
		"one hour window": {DomainSID: testDomainSID, Services: []string{"nfs/localhost"}, UnmarkedWindow: time.Hour},
	} {
		now = now0
		s, _ := d7Server(t, aliceDir(t), p)
		tkt, sk := unmarkedTGT(t, s, s.started.Add(-time.Hour))
		now = func() time.Time { return s.started.Add(2 * time.Hour) }
		if got := krbErrorCode(t, buy(t, s, tkt, sk, nfsSName, nil)); got != errorcode.KDC_ERR_TGT_REVOKED {
			t.Errorf("%s: error %d", name, got)
		}
	}
	now = now0
	s, _ := d7Server(t, aliceDir(t), &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}, RefuseUnmarked: true})
	tkt, sk := unmarkedTGT(t, s, s.started.Add(-time.Hour))
	if got := krbErrorCode(t, buy(t, s, tkt, sk, nfsSName, nil)); got != errorcode.KDC_ERR_TGT_REVOKED {
		t.Errorf("refuse at once: error %d", got)
	}
}

func TestTheMintedRIDIsConfigurable(t *testing.T) {
	s, kt := d7Server(t, aliceDir(t), &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}, MintedRID: 4000000000 >> 1})
	tkt, sk := mintedTGT(t, s, "federated")
	wantLogon(t, "custom RID", buy(t, s, tkt, sk, nfsSName, nil), kt, "S-1-18-1", testDomainSID+"-2000000000")
}

func TestPACConfigRefusesWhatD7CannotServe(t *testing.T) {
	for name, p := range map[string]*PAC{
		"a negative window":    {DomainSID: testDomainSID, UnmarkedWindow: -time.Second},
		"a window past 10 h":   {DomainSID: testDomainSID, UnmarkedWindow: MaxUnmarkedWindow + time.Second},
		"a minted RID of 2^31": {DomainSID: testDomainSID, MintedRID: 1 << 31},
	} {
		if _, err := New(Config{Realm: testRealm, People: aliceDir(t), Services: testKeytab(t), PAC: p}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestMintNeedsAKnownMethodWhenThePACIsOn(t *testing.T) {
	s, _ := d7Server(t, aliceDir(t), nil)
	for _, m := range []string{"", "password", "Passkey", "bridge-passkey", "passkey "} {
		if _, err := s.Mint(MintRequest{Principal: "alice", Method: m}); !errors.Is(err, ErrMintBadMethod) {
			t.Errorf("method %q: %v", m, err)
		}
	}
	// Off: optional, but never a value outside the list.
	off := mintServer(t, "https://login.example.org")
	if _, err := off.Mint(MintRequest{Principal: "alice@univ.example"}); err != nil {
		t.Errorf("no PAC, no method: %v", err)
	}
	if _, err := off.Mint(MintRequest{Principal: "alice@univ.example", Method: "passkey"}); err != nil {
		t.Errorf("no PAC, a method: %v", err)
	}
	if _, err := off.Mint(MintRequest{Principal: "alice@univ.example", Method: "nope"}); !errors.Is(err, ErrMintBadMethod) {
		t.Errorf("no PAC, an unknown method: %v", err)
	}
	// With the PAC off the TGT is what v0.12 made: no authorization data.
	raw, _ := off.Mint(MintRequest{Principal: "alice@univ.example", Method: "passkey"})
	var cred messages.KRBCred
	if err := cred.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	k, _, _ := off.cfg.Services.GetEncryptionKey(tgtSName, testRealm, 0, defaultEtype)
	if err := cred.Tickets[0].Decrypt(k); err != nil {
		t.Fatal(err)
	}
	if n := len(cred.Tickets[0].DecryptedEncPart.AuthorizationData); n != 0 {
		t.Errorf("a PAC-less realm's TGT carries %d authorization data", n)
	}
}

func TestMintHandlerAnswers400ForABadMethod(t *testing.T) {
	s, _ := d7Server(t, aliceDir(t), nil)
	p := newPKI(t)
	srv := httptest.NewUnstartedServer(s.MintHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.leaf(t, "", x509.ExtKeyUsageServerAuth)},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.caPool}
	srv.StartTLS()
	defer srv.Close()
	good := p.leaf(t, "https://login.example.org", x509.ExtKeyUsageClientAuth)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: p.caPool, ServerName: "localhost", Certificates: []tls.Certificate{good}}}}
	post := func(body string) int {
		resp, err := c.Post(srv.URL, "application/json", bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	for _, body := range []string{`{"principal":"alice"}`, `{"principal":"alice","method":"smoke-signal"}`} {
		if got := post(body); got != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", body, got)
		}
	}
	b, _ := json.Marshal(MintRequest{Principal: "alice", Method: "passkey"})
	if got := post(string(b)); got != http.StatusOK {
		t.Errorf("a good request: %d", got)
	}
	// Unknown fields are still refused.
	if got := post(`{"principal":"alice","method":"passkey","admin":true}`); got != http.StatusBadRequest {
		t.Errorf("an unknown field: %d", got)
	}
}

// newTGT reports every step that fails; none of them yields a ticket.
func TestNewTGTRefusesWhateverFailsWhileMakingIt(t *testing.T) {
	s, _ := d7Server(t, aliceDir(t), nil)
	n := now().UTC()
	mk := func(s *Server) error {
		_, _, err := s.newTGT(aliceName, types.NewKrbFlags(), n, n, n.Add(time.Hour), cammac.Claims{UID: 1001})
		return err
	}
	if err := mk(s); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	a, b, c, d := getEtype, genKey, marshalASN1, encryptWith
	t.Cleanup(func() { getEtype, genKey, marshalASN1, encryptWith = a, b, c, d })
	reset := func() { getEtype, genKey, marshalASN1, encryptWith = a, b, c, d }
	for name, set := range map[string]func(){
		"etype":   func() { getEtype = func(int32) (etype.EType, error) { return nil, boom } },
		"genkey":  func() { genKey = func(etype.EType) (types.EncryptionKey, error) { return types.EncryptionKey{}, boom } },
		"marshal": func() { marshalASN1 = func(any) ([]byte, error) { return nil, boom } },
		"encrypt": func() {
			encryptWith = func([]byte, types.EncryptionKey, uint32, int) (types.EncryptedData, error) {
				return types.EncryptedData{}, boom
			}
		},
	} {
		reset()
		set()
		if err := mk(s); err == nil {
			t.Errorf("%s failing: a ticket", name)
		}
	}
	reset()
	// No krbtgt key.
	empty := keytab.New()
	if err := empty.AddEntry("nfs/localhost", testRealm, "x", time.Now(), 2, 18); err != nil {
		t.Fatal(err)
	}
	real := s.cfg.Services
	s.cfg.Services = empty
	if err := mk(s); err == nil || !strings.Contains(err.Error(), "no krbtgt key") {
		t.Errorf("no krbtgt key: %v", err)
	}
	// A krbtgt key whose type cannot carry a CAMMAC checksum (rc4-hmac).
	rc4 := keytab.New()
	if err := rc4.AddEntry("krbtgt/"+testRealm, testRealm, "x", time.Now(), 2, 23); err != nil {
		t.Fatal(err)
	}
	s.cfg.Services = rc4
	if err := mk(s); err == nil {
		t.Error("an rc4 krbtgt key: a ticket")
	}
	s.cfg.Services = real
	// A marking the container cannot say (an unknown method).
	if _, _, err := s.newTGT(aliceName, types.NewKrbFlags(), n, n, n.Add(time.Hour), cammac.Claims{Methods: []string{"nope"}}); err == nil {
		t.Error("an unsayable marking: a ticket")
	}
	if err := (&Config{}).checkD7(); err != nil {
		t.Errorf("no PAC: %v", err)
	}
}

// The AS looks the person up again to mark the TGT; whichever read of the
// directory fails, the answer is an error, never a TGT.
func TestTheASRefusesWhenTheDirectoryFailsWhileMarking(t *testing.T) {
	for n := 1; n <= 6; n++ {
		d := aliceDir(t)
		s, _ := d7Server(t, d, nil)
		id, err := s.lookup(aliceName)
		if err != nil {
			t.Fatal(err)
		}
		key, err := s.cfg.keyFor(id)
		if err != nil {
			t.Fatal(err)
		}
		d.calls, d.failFrom = 0, n
		out := s.handle(asReq(t, "alice", krbtgtName, timestampPA(t, key, now().UTC())))
		var as messages.ASRep
		if as.Unmarshal(out) == nil && d.calls >= n {
			t.Errorf("failing from read %d: a TGT was issued", n)
		}
	}
}
