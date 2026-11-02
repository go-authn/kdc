// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Bibliography opened for these: MIT krb5 src/kdc/replay.c (the lookaside:
// keyed by the request packet, STALE_TIME 2 minutes, LOOKASIDE_MAX_SIZE
// 10 MiB, oldest discarded first), src/kdc/dispatch.c (a hit resends the
// stored reply, an in-progress copy is dropped, only a zero code is stored),
// src/kdc/kdc_util.c kdc_process_tgs_req ("Don't use a replay cache");
// RFC 4120 3.2.3, 5.4.2 (AS-REP and TGS-REP are APPLICATION 11 and 13), 7.5.9.

// resetLookaside empties the lookaside between benchmark rounds.
func resetLookaside(s *Server) { s.lookaside = newLookaside() }

// tgsAt builds a TGS-REQ for the named client whose authenticator says ctime
// and cusec, carrying a TGT valid around the fake clock's present.
func tgsAt(t testing.TB, s *Server, client string, ctime time.Time, cusec int) []byte {
	t.Helper()
	tgtSName := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	cn := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{client}}
	n := now()
	tkt, sk, err := messages.NewTicket(cn, testRealm, tgtSName, testRealm, types.NewKrbFlags(), s.cfg.Services,
		defaultEtype, 2, n.Add(-time.Minute), n.Add(-time.Minute), n.Add(10*time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	body := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		Till:  n.Add(time.Hour), Nonce: 7, EType: []int32{defaultEtype}}
	bb, err := body.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ck := bodyChecksum(t, sk)(bb)
	auth := types.Authenticator{AVNO: iana.PVNO, CRealm: testRealm, CName: cn, Cusec: cusec, CTime: ctime, SeqNumber: 1, Cksum: ck}
	ab, err := auth.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ed, err := crypto.GetEncryptedData(ab, sk, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR, 0)
	if err != nil {
		t.Fatal(err)
	}
	apb, err := (&messages.APReq{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REQ, APOptions: types.NewKrbFlags(),
		Ticket: tkt, EncryptedAuthenticator: ed}).Marshal()
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

// fakeClock replaces the package clock for one test.
func fakeClock(t testing.TB, start time.Time) *atomic.Int64 {
	t.Helper()
	var ns atomic.Int64
	ns.Store(start.UnixNano())
	orig := now
	now = func() time.Time { return time.Unix(0, ns.Load()) }
	t.Cleanup(func() { now = orig })
	return &ns
}

func twoPeople(t testing.TB, cfg func(*Config)) *Server {
	t.Helper()
	kt := keytab.New()
	for _, p := range []string{"krbtgt/" + testRealm, "nfs/localhost"} {
		if err := kt.AddEntry(p, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
			t.Fatal(err)
		}
	}
	c := Config{Realm: testRealm, Services: kt, Logf: t.Logf, People: manyPeople{
		directory.NewIdentity("alice", directory.WithPassword("alicepw")),
		directory.NewIdentity("bob", directory.WithPassword("bobpw")),
	}}
	if cfg != nil {
		cfg(&c)
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func issued(t testing.TB, out []byte) bool {
	t.Helper()
	var rep messages.TGSRep
	return rep.Unmarshal(out) == nil
}

// switchable is a Source an outage can be switched on and off in.
type switchable struct {
	people manyPeople
	down   atomic.Bool
	calls  atomic.Int32
}

func (s *switchable) Identities() ([]*directory.Identity, error) {
	s.calls.Add(1)
	if s.down.Load() {
		return brokenSource{}.Identities()
	}
	return s.people, nil
}
func (s *switchable) Describe() string                 { return "switchable" }
func (s *switchable) Members(string) ([]string, error) { return nil, nil }

func withSwitch(t *testing.T) (*Server, *switchable) {
	t.Helper()
	src := &switchable{people: manyPeople{directory.NewIdentity("alice", directory.WithPassword("alicepw"))}}
	return twoPeople(t, func(c *Config) { c.People = src }), src
}

// The reason the lookaside exists, and why it is not a replay cache: a client
// that lost the reply sends the same bytes again and gets the same reply —
// not KRB_AP_ERR_REPEAT, and without the request being worked a second time.
func TestARetransmittedRequestGetsTheSameReply(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	s, src := withSwitch(t)
	req := tgsAt(t, s, "alice", now(), 5)
	first := s.handle(req)
	if !issued(t, first) {
		t.Fatalf("the first TGS-REQ was refused, code %d", krbErrorCode(t, first))
	}
	calls := src.calls.Load()
	// Even with the directory down: the copy is not looked at again.
	src.down.Store(true)
	again := s.handle(req)
	if !bytes.Equal(again, first) {
		t.Errorf("the retransmission got another reply (%d bytes, code %d)", len(again), krbErrorCode(t, again))
	}
	if n := src.calls.Load(); n != calls {
		t.Errorf("the retransmission read the directory %d more times, want 0", n-calls)
	}
}

// Distinct requests are each answered on their own; nothing here refuses an
// authenticator for having been seen.
func TestDistinctRequestsAreEachServed(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	s := twoPeople(t, nil)
	ct := now()
	for name, req := range map[string][]byte{
		"base":          tgsAt(t, s, "alice", ct, 5),
		"another cusec": tgsAt(t, s, "alice", ct, 6),
		"another ctime": tgsAt(t, s, "alice", ct.Add(time.Second), 5),
		"another user":  tgsAt(t, s, "bob", ct, 5),
	} {
		if out := s.handle(req); !issued(t, out) {
			t.Errorf("%s: refused, code %d", name, krbErrorCode(t, out))
		}
	}
	if n := s.lookaside.len(); n != 4 {
		t.Errorf("%d entries, want 4", n)
	}
}

// A KRB-ERROR is not stored: a client told the service is unavailable that
// retries the same bytes is served once the directory is back.
func TestAnErrorIsNotStored(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	s, src := withSwitch(t)
	req := tgsAt(t, s, "alice", now(), 1)
	src.down.Store(true)
	if got := krbErrorCode(t, s.handle(req)); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
		t.Fatalf("directory down: code %d, want KDC_ERR_SVC_UNAVAILABLE (29)", got)
	}
	if n := s.lookaside.len(); n != 0 {
		t.Errorf("%d entries after an error, want 0", n)
	}
	src.down.Store(false)
	if out := s.handle(req); !issued(t, out) {
		t.Errorf("the same bytes once the directory is back: code %d, want a ticket", krbErrorCode(t, out))
	}
}

// An entry is stale after two minutes: the same bytes then are worked again.
func TestALookasideEntryGoesStale(t *testing.T) {
	clock := fakeClock(t, time.Now().Truncate(time.Second))
	s, src := withSwitch(t)
	req := tgsAt(t, s, "alice", now(), 1)
	if !issued(t, s.handle(req)) {
		t.Fatal("refused")
	}
	src.down.Store(true)
	clock.Add(int64(lookasideStale))
	if !issued(t, s.handle(req)) {
		t.Error("at exactly two minutes the entry is still fresh (MIT: stale strictly after)")
	}
	clock.Add(int64(time.Second))
	// Any insertion purges what is stale; the request itself makes one.
	if got := krbErrorCode(t, s.handle(req)); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
		t.Errorf("past two minutes: code %d, want the request worked again (29, the directory is down)", got)
	}
}

// A copy that arrives while the original is being worked on is dropped, as
// MIT does: the client retransmits again and by then there is a reply.
func TestACopyDuringProcessingIsDropped(t *testing.T) {
	c := newLookaside()
	req := []byte("a request")
	if _, hit := c.enter(req); hit {
		t.Fatal("first sighting reported as a hit")
	}
	if rep, hit := c.enter(req); !hit || rep != nil {
		t.Errorf("a copy during processing: hit %v, %d-byte reply; want a hit with no reply", hit, len(rep))
	}
	c.finish(req, []byte{0x6d, 0})
	if rep, hit := c.enter(req); !hit || !bytes.Equal(rep, []byte{0x6d, 0}) {
		t.Errorf("after the reply: hit %v, reply %x", hit, rep)
	}
}

// panicky is a Source whose read panics, as a broken backend might.
type panicky struct{}

func (panicky) Identities() ([]*directory.Identity, error) { panic("backend bug") }
func (panicky) Describe() string                           { return "panicky" }
func (panicky) Members(string) ([]string, error)           { return nil, nil }

// A request that panicked leaves no in-progress entry behind: otherwise every
// copy of it would be dropped until the entry went stale.
func TestAPanicLeavesNoEntry(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	s := twoPeople(t, func(c *Config) { c.People = panicky{} })
	req := tgsAt(t, s, "alice", now(), 1)
	if out := s.handle(req); out != nil {
		t.Fatalf("a panic produced a %d-byte reply", len(out))
	}
	if n := s.lookaside.len(); n != 0 {
		t.Errorf("%d entries after a panic, want 0", n)
	}
}

// The size bound: entries together stay under 10 MiB, the oldest go first.
func TestLookasideStaysUnderItsSize(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	c := newLookaside()
	rep := append([]byte{0x6b}, make([]byte, 64<<10)...)
	const n = 400 // 400 × 64 KiB = 25 MiB offered
	for i := 0; i < n; i++ {
		req := []byte(strings.Repeat("r", 10) + string(rune('A'+i%26)) + time.Duration(i).String())
		c.enter(req)
		c.finish(req, rep)
		if c.size > lookasideMaxSize {
			t.Fatalf("after %d: %d bytes held, the bound is %d", i, c.size, lookasideMaxSize)
		}
	}
	if c.len() >= n || c.len() == 0 {
		t.Fatalf("%d entries held", c.len())
	}
	first := []byte(strings.Repeat("r", 10) + "A" + time.Duration(0).String())
	if _, hit := c.enter(first); hit {
		t.Error("the oldest entry survived the size bound")
	}
}

// Only an AS-REP or a TGS-REP is worth resending.
func TestIsReply(t *testing.T) {
	for b, want := range map[byte]bool{0x6b: true, 0x6d: true, 0x7e: false, 0x6a: false, 0x6c: false} {
		if got := isReply([]byte{b, 0}); got != want {
			t.Errorf("isReply(%#x) = %v", b, got)
		}
	}
	if isReply(nil) {
		t.Error("isReply(nil)")
	}
}

// Many goroutines, a few requests, through handle. Run with -race. Every
// reply is either a ticket, or nothing (a copy during processing).
func TestLookasideUnderConcurrency(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	s := twoPeople(t, nil)
	reqs := [][]byte{tgsAt(t, s, "alice", now(), 1), tgsAt(t, s, "alice", now(), 2), tgsAt(t, s, "bob", now(), 1)}
	var wg sync.WaitGroup
	var bad atomic.Int32
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				if out := s.handle(reqs[i%len(reqs)]); out != nil && !issued(t, out) {
					bad.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Errorf("%d replies were neither a ticket nor a drop", n)
	}
	if n := s.lookaside.len(); n != len(reqs) {
		t.Errorf("%d entries, want %d", n, len(reqs))
	}
}

// authnd#74: an outage of the directory is never reported as a wrong
// password, on either path, and with a CORRECT pre-authentication too — the
// case that would otherwise be checked.
func TestAnOutageIsNeverAWrongPassword(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	s, src := withSwitch(t)
	id := src.people[0]
	key, err := s.cfg.keyFor(id)
	if err != nil {
		t.Fatal(err)
	}
	asOK := asReq(t, "alice", []string{"krbtgt", testRealm}, timestampPA(t, key, now()))
	tgs := tgsAt(t, s, "alice", now(), 9)
	src.down.Store(true)
	for name, req := range map[string][]byte{"AS-REQ, right password": asOK, "TGS-REQ": tgs} {
		if got := krbErrorCode(t, s.handle(req)); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
			t.Errorf("%s, directory down: code %d, want KDC_ERR_SVC_UNAVAILABLE (29), never PREAUTH_FAILED (24)", name, got)
		}
	}
	// And the same bytes once it is back are what they always were.
	src.down.Store(false)
	var rep messages.ASRep
	if err := rep.Unmarshal(s.handle(asOK)); err != nil {
		t.Errorf("AS-REQ once the directory is back: %v", err)
	}
}

// authnd#74, the other half: an upstream `ldap` source gives Verifiers — a bind
// against somebody else's directory. Kerberos cannot use one, so the KDC
// never asks the upstream to check a password: the verifier is not called, and
// the answer is KDC_ERR_NULL_KEY, a configuration to fix, not a wrong password.
func TestAVerifierIsNeverAskedByKerberos(t *testing.T) {
	var asked atomic.Int32
	id := directory.NewIdentity("alice", directory.WithVerifier(func(string) error {
		asked.Add(1)
		return errors.New("the upstream directory is unreachable")
	}))
	s := testServer(t, id)
	pa := timestampPA(t, types.EncryptionKey{KeyType: defaultEtype, KeyValue: make([]byte, 32)}, time.Now())
	for name, p := range map[string]types.PADataSequence{"without preauth": nil, "with preauth": pa} {
		if got := errorCode(t, s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, p))); got != errorcode.KDC_ERR_NULL_KEY {
			t.Errorf("%s: code %d, want KDC_ERR_NULL_KEY (9)", name, got)
		}
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("the upstream was asked %d times", n)
	}
}
