// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc/internal/cammac"
	"github.com/go-authn/kdc/internal/pac"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// dirPeople is a directory with groups, whose reads can be made to fail: the
// Nth call of Identities onward (failFrom, 1-based; 0 never), GroupNames, or
// one group's attributes.
type dirPeople struct {
	ids       []*directory.Identity
	groupList []string
	gids      map[string]string // group -> gidNumber ("" none)
	badGroup  string            // GroupAttributes fails for it
	namesErr  error

	failFrom int
	calls    int
}

var errDirBroke = errors.New("the directory broke")

func (d *dirPeople) Identities() ([]*directory.Identity, error) {
	d.calls++
	if d.failFrom > 0 && d.calls >= d.failFrom {
		return nil, errDirBroke
	}
	return d.ids, nil
}
func (d *dirPeople) Describe() string                 { return "a directory with groups" }
func (d *dirPeople) Members(string) ([]string, error) { return nil, nil }
func (d *dirPeople) GroupNames() ([]string, error)    { return d.groupList, d.namesErr }
func (d *dirPeople) GroupAttributes(g string) (directory.Attributes, error) {
	if g == d.badGroup {
		return directory.Attributes{}, errDirBroke
	}
	var at []directory.Attribute
	if gid := d.gids[g]; gid != "" {
		at = append(at, directory.Attribute{Name: "gidNumber", Values: []string{gid}})
	}
	return directory.NewAttributes(at...)
}

func ticketFor(t *testing.T, people directory.Source, kt *keytab.Keytab) []byte {
	t.Helper()
	s, err := New(Config{Realm: testRealm, People: people, Services: kt, Logf: t.Logf, AllowPasswordDerivedAS: true,
		PAC: &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}}})
	if err != nil {
		t.Fatal(err)
	}
	return tgsOnce(t, s)
}

func tgsOnce(t *testing.T, s *Server) []byte {
	t.Helper()
	// An unmarked TGT from before the server started (D7: still accepted).
	n := now().UTC()
	out, _ := tgsWith(t, s, s.started.Add(-time.Minute), n.Add(time.Hour), n.Add(time.Hour), false)
	return out
}

func testKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	for _, n := range []string{"krbtgt/" + testRealm, "nfs/localhost"} {
		if err := kt.AddEntry(n, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
			t.Fatal(err)
		}
	}
	return kt
}

func eText(t *testing.T, out []byte) string {
	t.Helper()
	var e messages.KRBError
	if err := e.Unmarshal(out); err != nil {
		t.Fatalf("not a KRB-ERROR: %v", err)
	}
	return e.EText
}

// logonOf decodes the LOGON_INFO of a ticket the KDC just issued.
func logonOf(t *testing.T, out []byte, kt *keytab.Keytab) *pac.LogonInfo {
	t.Helper()
	var rep messages.TGSRep
	if err := rep.Unmarshal(out); err != nil {
		t.Fatalf("no ticket (error %d, %q)", krbErrorCode(t, out), eText(t, out))
	}
	key, _, err := kt.GetEncryptionKey(rep.Ticket.SName, testRealm, 0, defaultEtype)
	if err != nil {
		t.Fatal(err)
	}
	if err := rep.Ticket.Decrypt(key); err != nil {
		t.Fatal(err)
	}
	pb, _ := pacOf(t, rep.Ticket)
	p, err := pac.Parse(pb)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.Buffer(pac.TypeLogonInfo)
	li, err := pac.UnmarshalLogonInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	return li
}

func rids(gs []pac.Group) []uint32 {
	var out []uint32
	for _, g := range gs {
		out = append(out, g.RID)
	}
	return out
}

func TestGroupsOfAPACAreTheDirectorysNumberedOnes(t *testing.T) {
	kt := testKeytab(t)
	d := &dirPeople{
		ids:       []*directory.Identity{person(t, "alice", "1001", "1000", "staff", "nogid", "broken", "alias", "primary")},
		groupList: []string{"staff", "nogid", "broken"}, // alias and primary are alice's only
		gids:      map[string]string{"staff": "2000", "alias": "2000", "primary": "1000"},
		badGroup:  "broken",
	}
	li := logonOf(t, ticketFor(t, d, kt), kt)
	// the primary group, then staff; nogid has no number, broken cannot be read,
	// alias repeats staff's number, primary repeats the primary group's.
	if got := rids(li.Groups); len(got) != 2 || got[0] != 1000 || got[1] != 2000 {
		t.Errorf("groups %v", got)
	}
}

func TestPACGroupsAreCapped(t *testing.T) {
	for _, extra := range []int{254, 255, 256, 400} {
		kt := testKeytab(t)
		var names []string
		gids := map[string]string{}
		for i := 0; i < extra; i++ {
			n := fmt.Sprintf("g%d", i)
			names = append(names, n)
			gids[n] = fmt.Sprint(5000 + i)
		}
		d := &dirPeople{ids: []*directory.Identity{person(t, "alice", "1001", "1000", names...)}, groupList: names, gids: gids}
		li := logonOf(t, ticketFor(t, d, kt), kt)
		want := min(1+extra, maxPACGroups)
		if len(li.Groups) != want {
			t.Errorf("%d groups in the directory: %d in the PAC, want %d", extra, len(li.Groups), want)
		}
	}
}

func TestADirectoryThatListsAGroupTwiceIsNotAClash(t *testing.T) {
	kt := testKeytab(t)
	d := &dirPeople{
		// alice appears twice, and staff twice: the same name is the same account.
		ids:       []*directory.Identity{person(t, "alice", "1001", "1000", "staff"), person(t, "alice", "1001", "1000", "staff")},
		groupList: []string{"staff", "staff", "other"},
		gids:      map[string]string{"staff": "2000", "other": "2001"},
	}
	if li := logonOf(t, ticketFor(t, d, kt), kt); len(li.Groups) != 2 {
		t.Errorf("groups %v", rids(li.Groups))
	}
}

func TestTwoGroupsOneNumberRefused(t *testing.T) {
	kt := testKeytab(t)
	d := &dirPeople{
		ids:       []*directory.Identity{person(t, "alice", "1001", "1000", "staff")},
		groupList: []string{"staff", "twin"},
		gids:      map[string]string{"staff": "2000", "twin": "2000"},
	}
	out := ticketFor(t, d, kt)
	if got := krbErrorCode(t, out); got != errorcode.KDC_ERR_POLICY {
		t.Errorf("error %d, want KDC_ERR_POLICY", got)
	}
}

func TestDirectoryFailuresAreAnOutageNotATicket(t *testing.T) {
	// Per TGS request the directory is read: the lookup at the TGS (1), the
	// lookup in the PAC code (2), the number table (3).
	for call := 1; call <= 3; call++ {
		kt := testKeytab(t)
		d := &dirPeople{ids: []*directory.Identity{person(t, "alice", "1001", "1000")}, failFrom: call}
		out := ticketFor(t, d, kt)
		if got := krbErrorCode(t, out); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
			t.Errorf("read %d failing: error %d, want KDC_ERR_SVC_UNAVAILABLE", call, got)
		}
	}
	// The group list failing is the same outage.
	kt := testKeytab(t)
	d := &dirPeople{ids: []*directory.Identity{person(t, "alice", "1001", "1000")}, namesErr: errDirBroke}
	out := ticketFor(t, d, kt)
	if got := krbErrorCode(t, out); got != errorcode.KDC_ERR_SVC_UNAVAILABLE || !strings.Contains(eText(t, out), errDirBroke.Error()) {
		t.Errorf("group list failing: error %d %q", got, eText(t, out))
	}
}

func TestTheNumberTableIsRefreshedAfterItsTTLNotBefore(t *testing.T) {
	kt := testKeytab(t)
	d := &dirPeople{ids: []*directory.Identity{person(t, "alice", "1001", "1000"), person(t, "mallory", "1002", "1000")}}
	s, err := New(Config{Realm: testRealm, People: d, Services: kt, Logf: t.Logf, AllowPasswordDerivedAS: true,
		PAC: &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}}})
	if err != nil {
		t.Fatal(err)
	}
	if li := logonOf(t, tgsOnce(t, s), kt); li.UserID != 1001 {
		t.Fatalf("uid %d", li.UserID)
	}
	// Within the TTL the table is not read again: alice's number changes to one
	// nobody held when it was read, and that is no clash.
	d.ids = []*directory.Identity{person(t, "alice", "1005", "1000")}
	if li := logonOf(t, tgsOnce(t, s), kt); li.UserID != 1005 {
		t.Fatalf("uid %d", li.UserID)
	}
	// Within the TTL, a stale table that says 1001 is alice's still lets alice
	// keep 1001 when she holds it again.
	d.ids = []*directory.Identity{person(t, "alice", "1001", "1000"), person(t, "mallory", "1001", "1000")}
	if got := krbErrorCode2(t, tgsOnce(t, s)); got != 0 {
		t.Errorf("a clash that appeared within the TTL was caught early: error %d", got)
	}
	// The table is stale, not ignored: it still says 1002 is mallory's, so alice
	// taking 1002 within the TTL is refused by it.
	d.ids = []*directory.Identity{person(t, "alice", "1002", "1000")}
	if got := krbErrorCode2(t, tgsOnce(t, s)); got != errorcode.KDC_ERR_POLICY {
		t.Errorf("a number the table gives another: error %d, want KDC_ERR_POLICY", got)
	}
	// After the TTL the table is read again and the clash is found.
	d.ids = []*directory.Identity{person(t, "alice", "1001", "1000"), person(t, "mallory", "1001", "1000")}
	orig := now
	t.Cleanup(func() { now = orig })
	now = func() time.Time { return orig().Add(2 * ridTTL) }
	if got := krbErrorCode(t, tgsOnce(t, s)); got != errorcode.KDC_ERR_POLICY {
		t.Errorf("after the TTL: error %d, want KDC_ERR_POLICY", got)
	}
}

// krbErrorCode2 is 0 for a ticket, the error code for a refusal.
func krbErrorCode2(t *testing.T, out []byte) int32 {
	t.Helper()
	var e messages.KRBError
	if err := e.Unmarshal(out); err != nil {
		return 0
	}
	return e.ErrorCode
}

func TestAnIssuanceFailureIsReportedNotSwallowed(t *testing.T) {
	boom := errors.New("injected failure")
	type undo func()
	swap := func() undo {
		a, b, c, d, e := getEtype, genKey, marshalASN1, encryptWith, randRead
		return func() { getEtype, genKey, marshalASN1, encryptWith, randRead = a, b, c, d, e }
	}
	cases := map[string]func(kt *keytab.Keytab){
		"etype": func(*keytab.Keytab) {
			getEtype = func(int32) (etype.EType, error) { return nil, boom }
		},
		"session key": func(*keytab.Keytab) {
			genKey = func(etype.EType) (types.EncryptionKey, error) { return types.EncryptionKey{}, boom }
		},
		"service key": func(kt *keytab.Keytab) { // the entry vanishes while the ticket is made
			orig := genKey
			genKey = func(et etype.EType) (types.EncryptionKey, error) {
				keep := kt.Entries[:0:0]
				for _, e := range kt.Entries {
					if e.Principal.Components[0] != "nfs" {
						keep = append(keep, e)
					}
				}
				kt.Entries = keep
				return orig(et)
			}
		},
		"krbtgt key": func(kt *keytab.Keytab) {
			orig := genKey
			genKey = func(et etype.EType) (types.EncryptionKey, error) {
				keep := kt.Entries[:0:0]
				for _, e := range kt.Entries {
					if e.Principal.Components[0] != "krbtgt" {
						keep = append(keep, e)
					}
				}
				kt.Entries = keep
				return orig(et)
			}
		},
		"seal": func(*keytab.Keytab) {
			encryptWith = func([]byte, types.EncryptionKey, uint32, int) (types.EncryptedData, error) {
				return types.EncryptedData{}, boom
			}
		},
	}
	// Each of the four marshalings of a ticket, in order: the PAC wrapper and
	// the EncTicketPart of the signed copy, then of the final one.
	for i := 1; i <= 4; i++ {
		i := i
		cases[fmt.Sprintf("marshal %d", i)] = func(*keytab.Keytab) {
			n := 0
			orig := marshalASN1
			marshalASN1 = func(v any) ([]byte, error) {
				if n++; n == i {
					return nil, boom
				}
				return orig(v)
			}
		}
	}
	for name, fail := range cases {
		kt := testKeytab(t)
		restore := swap()
		fail(kt)
		out := ticketFor(t, peopleList{person(t, "alice", "1001", "1000")}, kt)
		restore()
		code := krbErrorCode(t, out)
		if code != errorcode.KDC_ERR_SVC_UNAVAILABLE {
			t.Errorf("%s: error %d, want KDC_ERR_SVC_UNAVAILABLE", name, code)
			continue
		}
		// The refusal says what failed, not what a swallowed failure breaks later.
		txt := eText(t, out)
		switch name {
		case "service key":
			if !strings.Contains(txt, "matching key not found") || !strings.Contains(txt, "nfs/localhost") {
				t.Errorf("%s: %q", name, txt)
			}
		case "krbtgt key":
			if !strings.Contains(txt, "matching key not found") || !strings.Contains(txt, "krbtgt/") {
				t.Errorf("%s: %q", name, txt)
			}
		default:
			if !strings.Contains(txt, boom.Error()) {
				t.Errorf("%s: %q", name, txt)
			}
		}
	}
}

func TestAPACRefusesAClientTheBuilderCannotEncode(t *testing.T) {
	// A name too long for LOGON_INFO: pac.Build refuses, and so does the KDC.
	long := strings.Repeat("a", pac.MaxStringUnits+1)
	kt := testKeytab(t)
	s, err := New(Config{Realm: testRealm, People: peopleList{person(t, long, "1001", "1000")}, Services: kt, Logf: t.Logf,
		PAC: &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}}})
	if err != nil {
		t.Fatal(err)
	}
	st := s.pacState()
	id := person(t, long, "1001", "1000")
	li, usid, err := s.logonInfo(st, id, time.Unix(5, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pac.Build(&pac.Input{Logon: li, ClientName: long, AuthTime: time.Unix(5, 0), UserSID: usid, RequestorSID: usid}, key18(), key18()); !errors.Is(err, pac.ErrTooBig) {
		t.Errorf("a long name: %v", err)
	}
	// And through the KDC: the principal exists but cannot be given a PAC.
	s2, err := New(Config{Realm: testRealm, People: peopleList{person(t, long, "1001", "1000")}, Services: kt, Logf: t.Logf,
		PAC: &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s2.pacTicket(types.PrincipalName{NameType: nametypePrincipal, NameString: []string{long}},
		types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		types.NewKrbFlags(), 2, time.Unix(5, 0), time.Unix(5, 0), time.Unix(3600, 0), cammac.Claims{})
	if !errors.Is(err, pac.ErrTooBig) {
		t.Errorf("pacTicket for a name too long: %v", err)
	}
}

func key18() types.EncryptionKey {
	return types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}
}

func TestNewDomainSIDReportsAFailingSource(t *testing.T) {
	orig := randRead
	t.Cleanup(func() { randRead = orig })
	randRead = func([]byte) (int, error) { return 0, errDirBroke }
	if sid, err := NewDomainSID(); !errors.Is(err, errDirBroke) || sid != "" {
		t.Errorf("%q %v", sid, err)
	}
	randRead = orig
	a, err := NewDomainSID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pac.ParseSID(a); err != nil {
		t.Error(err)
	}
}
