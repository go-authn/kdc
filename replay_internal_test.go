// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
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

// Bibliography opened for these: RFC 4120 3.2.3 (an AP-REQ's authenticator is
// accepted once, KRB_AP_ERR_REPEAT otherwise), 3.3.2 (the PA-TGS-REQ is an
// AP-REQ), 7.5.9 (KRB_AP_ERR_REPEAT is 34, KDC_ERR_SVC_UNAVAILABLE is 29);
// MIT krb5 lib/krb5/rcache (entries keyed by client, server, ctime, cusec,
// forgotten after the skew).

// resetReplay empties the replay cache between benchmark rounds.
func resetReplay(s *Server) { s.replay = newReplayCache(s.cfg.ReplayCacheEntries) }

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

// RFC 4120 3.2.3: the same authenticator, a second time, is KRB_AP_ERR_REPEAT.
func TestAReplayedAuthenticatorIsRefused(t *testing.T) {
	clock := fakeClock(t, time.Now().Truncate(time.Second))
	s := twoPeople(t, nil)
	req := tgsAt(t, s, "alice", now(), 5)
	if !issued(t, s.handle(req)) {
		t.Fatal("the first TGS-REQ was refused")
	}
	if got := krbErrorCode(t, s.handle(req)); got != errorcode.KRB_AP_ERR_REPEAT {
		t.Errorf("the same request again: code %d, want KRB_AP_ERR_REPEAT (34)", got)
	}
	// Still refused near the end of the window.
	clock.Add(int64(4 * time.Minute))
	if got := krbErrorCode(t, s.handle(req)); got != errorcode.KRB_AP_ERR_REPEAT {
		t.Errorf("4 minutes later: code %d, want KRB_AP_ERR_REPEAT", got)
	}
}

// The key is client, server, ctime, cusec: change any of the variable three
// and it is another authenticator.
func TestADifferentAuthenticatorIsAccepted(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	s := twoPeople(t, nil)
	ct := now()
	for name, req := range map[string][]byte{
		"base":              tgsAt(t, s, "alice", ct, 5),
		"another cusec":     tgsAt(t, s, "alice", ct, 6),
		"another ctime":     tgsAt(t, s, "alice", ct.Add(time.Second), 5),
		"another client":    tgsAt(t, s, "bob", ct, 5),
		"the earlier ctime": tgsAt(t, s, "alice", ct.Add(-time.Second), 5),
	} {
		if !issued(t, s.handle(req)) {
			t.Errorf("%s: refused, code %d", name, krbErrorCode(t, s.handle(req)))
		}
	}
}

// Entries live for the skew window and no longer: a replay after it is
// refused by the skew check instead, and the entry is gone.
func TestReplayEntriesExpireAfterTheWindow(t *testing.T) {
	clock := fakeClock(t, time.Now().Truncate(time.Second))
	s := twoPeople(t, func(c *Config) { c.MaxSkew = 2 * time.Minute })
	req := tgsAt(t, s, "alice", now(), 1)
	if !issued(t, s.handle(req)) {
		t.Fatal("refused")
	}
	if s.replay.len() != 1 {
		t.Fatalf("%d entries, want 1", s.replay.len())
	}
	clock.Add(int64(2*time.Minute + 2*time.Second))
	// Outside the window the authenticator is a skew error, never accepted.
	if got := krbErrorCode(t, s.handle(req)); got != errorcode.KRB_AP_ERR_SKEW {
		t.Errorf("after the window: code %d, want KRB_AP_ERR_SKEW", got)
	}
	// Any later admission sweeps the expired entry out.
	if !issued(t, s.handle(tgsAt(t, s, "alice", now(), 2))) {
		t.Fatal("a fresh authenticator was refused")
	}
	if s.replay.len() != 1 {
		t.Errorf("%d entries after the sweep, want 1 (the new one)", s.replay.len())
	}
}

// The cap: a full cache refuses with SVC_UNAVAILABLE, a repeat is still a
// repeat, and room comes back when entries expire.
func TestReplayCacheCapRefusesWhenFull(t *testing.T) {
	clock := fakeClock(t, time.Now().Truncate(time.Second))
	s := twoPeople(t, func(c *Config) { c.ReplayCacheEntries = 3 })
	ct := now()
	var reqs [][]byte
	for i := 0; i < 3; i++ {
		r := tgsAt(t, s, "alice", ct, i)
		reqs = append(reqs, r)
		if !issued(t, s.handle(r)) {
			t.Fatalf("request %d refused below the cap", i)
		}
	}
	over := tgsAt(t, s, "alice", ct, 99)
	if got := krbErrorCode(t, s.handle(over)); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
		t.Errorf("past the cap: code %d, want KDC_ERR_SVC_UNAVAILABLE (29)", got)
	}
	if s.replay.len() != 3 {
		t.Errorf("%d entries, the cap is 3", s.replay.len())
	}
	if got := krbErrorCode(t, s.handle(reqs[0])); got != errorcode.KRB_AP_ERR_REPEAT {
		t.Errorf("a repeat in a full cache: code %d, want KRB_AP_ERR_REPEAT", got)
	}
	// Room again once the window has passed.
	clock.Add(int64(5*time.Minute + 2*time.Second))
	if !issued(t, s.handle(tgsAt(t, s, "alice", now(), 100))) {
		t.Error("still refused after the entries expired")
	}
}

// The default applies to zero and to a negative number.
func TestReplayCacheDefaultCap(t *testing.T) {
	for _, n := range []int{0, -1} {
		if c := newReplayCache(n); c.max != DefaultReplayCacheEntries {
			t.Errorf("newReplayCache(%d).max = %d", n, c.max)
		}
	}
}

// Many goroutines, a few authenticators, each accepted exactly once. Run with
// -race.
func TestReplayCacheIsSafeUnderConcurrency(t *testing.T) {
	c := newReplayCache(1000)
	at := time.Now()
	var fresh [50]atomic.Int32
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				k := replayKey("R", "alice", "krbtgt/R@R", at, i)
				if c.admit(k, at.Add(time.Minute), at) == replayFresh {
					fresh[i].Add(1)
				}
			}
		}()
	}
	wg.Wait()
	for i := range fresh {
		if n := fresh[i].Load(); n != 1 {
			t.Errorf("authenticator %d accepted %d times, want 1", i, n)
		}
	}
}

// The key separates what it should, and nothing else.
func TestReplayKey(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	base := replayKey("R", "alice", "krbtgt/R@R", at, 1)
	for name, k := range map[string][32]byte{
		"realm":  replayKey("S", "alice", "krbtgt/R@R", at, 1),
		"client": replayKey("R", "alic", "krbtgt/R@R", at, 1),
		"server": replayKey("R", "alice", "krbtgt/S@S", at, 1),
		"ctime":  replayKey("R", "alice", "krbtgt/R@R", at.Add(time.Second), 1),
		"cusec":  replayKey("R", "alice", "krbtgt/R@R", at, 2),
		"shift":  replayKey("R", "alicekrbtgt/R@R", "", at, 1),
	} {
		if k == base {
			t.Errorf("a different %s gave the same key", name)
		}
	}
	if replayKey("R", "alice", "krbtgt/R@R", at, 1) != base {
		t.Error("the key is not deterministic")
	}
}

// A server hammered concurrently through handle: each distinct authenticator
// is issued once and a copy is refused.
func TestConcurrentTGSReqsAreEachIssuedOnce(t *testing.T) {
	fakeClock(t, time.Now().Truncate(time.Second))
	s := twoPeople(t, nil)
	req := tgsAt(t, s, "alice", now(), 3)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if issued(t, s.handle(req)) {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Errorf("one authenticator, 8 concurrent copies: %d issued, want 1", ok.Load())
	}
}
