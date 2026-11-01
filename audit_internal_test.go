// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Findings of the v0.4.5 audit (RFC 4120 3.1.3, 3.3.3; MIT kdc/do_as_req.c).

// asReqRealm is an AS-REQ whose KDC-REQ-BODY names the given realm.
func asReqRealm(t testing.TB, realm string, pa types.PADataSequence) []byte {
	t.Helper()
	body := messages.KDCReqBody{
		KDCOptions: types.NewKrbFlags(),
		CName:      types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}},
		Realm:      realm,
		SName:      types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", realm}},
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
	b, err := asn1.Marshal(marshalReq{PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REQ, PAData: pa, ReqBody: body})
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.ASREQ)
}

// A request for another realm is not ours to answer: RFC 4120 3.1.3 / MIT
// answers KDC_ERR_WRONG_REALM. Served as if it were ours, a client of a
// different realm that happens to share a principal name gets a TGT.
func TestAnotherRealmIsRefused(t *testing.T) {
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, id)
	key, err := s.cfg.keyFor(id)
	if err != nil {
		t.Fatal(err)
	}
	out := s.handle(asReqRealm(t, "OTHER.TEST", timestampPA(t, key, time.Now())))
	if got := errorCode(t, out); got != errorcode.KDC_ERR_WRONG_REALM {
		t.Errorf("code %d, want WRONG_REALM (68)", got)
	}
}

// A cipher whose declared etype is a smaller one than the key's passes the
// length check made with the DECLARED etype and then reaches the key's own
// decryption, which slices without looking.
func TestDeclaredEtypeDoesNotShortenTheCipherCheck(t *testing.T) {
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, id)
	for _, et := range []int32{17, 18, 23, 24, 0, -1, 1 << 30} {
		for n := 0; n <= 40; n++ {
			ed := types.EncryptedData{EType: et, Cipher: make([]byte, n)}
			raw, err := ed.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			pa := types.PADataSequence{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: raw}}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("etype %d, %d-byte cipher: PANIC %v", et, n, r)
					}
				}()
				s.handle(asReqRealm(t, testRealm, pa))
			}()
		}
	}
}

type brokenSource struct{}

func (brokenSource) Identities() ([]*directory.Identity, error) {
	return nil, errors.New("connection refused")
}
func (brokenSource) Describe() string                 { return "broken" }
func (brokenSource) Members(string) ([]string, error) { return nil, nil }

// A directory that cannot be read is an outage, not an unknown person: the
// client must be told to try again (KDC_ERR_SVC_UNAVAILABLE, as MIT does when
// the database is unavailable), not that the principal does not exist.
func TestDirectoryOutageIsNotAnUnknownPrincipal(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	s.cfg.People = brokenSource{}
	for name, pa := range map[string]types.PADataSequence{"without preauth": nil} {
		if got := errorCode(t, s.handle(asReqRealm(t, testRealm, pa))); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
			t.Errorf("%s: code %d, want SVC_UNAVAILABLE (29)", name, got)
		}
	}
}

// The TGT's times were written by this clock, but the clock can be stepped
// back (NTP, an operator): a TGT issued a moment ago must not be "not yet
// valid" for the whole of the step. MIT allows the configured skew on starttime.
func TestTGTStartedSlightlyInTheFutureIsAccepted(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	n := now().UTC()
	out, _ := tgsWith(t, s, n.Add(time.Minute), n.Add(time.Hour), n.Add(30*time.Minute), false)
	var rep messages.TGSRep
	if err := rep.Unmarshal(out); err != nil {
		t.Errorf("a TGT starting in a minute (inside the %v skew) was refused with code %d", s.cfg.skew(), krbErrorCode(t, out))
	}
	out, _ = tgsWith(t, s, n.Add(10*time.Minute), n.Add(time.Hour), n.Add(30*time.Minute), false)
	if got := krbErrorCode(t, out); got != errorcode.KRB_AP_ERR_TKT_NYV {
		t.Errorf("a TGT starting beyond the skew: code %d, want NYV", got)
	}
}

// Names come from the network: a newline in one must not forge a log line.
func TestLogsDoNotCarryRawControlCharacters(t *testing.T) {
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, id)
	var logged atomic.Value
	logged.Store("")
	s.cfg.Logf = func(f string, a ...any) { logged.Store(logged.Load().(string) + fmt.Sprintf(f, a...) + "\n") }
	key, _ := s.cfg.keyFor(id)
	s.handle(asReqRealm(t, "FORGED\nkdc: accepted alice", timestampPA(t, key, time.Now())))
	if strings.Contains(logged.Load().(string), "FORGED\n") {
		t.Errorf("a raw newline from the network reached the log:\n%s", logged.Load())
	}
}

// ⛔ Found by FuzzHandle: an AS-REQ whose additional-tickets field is
// malformed makes gokrb5 v8.4.4 (messages.unmarshalTicketsSequence, indexing
// the length header of a one-byte value) panic. It runs in the serving
// goroutine, before any authentication: one datagram killed the process.
func TestADecoderPanicCostsOneRequest(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	var recovered bool
	s.cfg.Logf = func(f string, a ...any) { recovered = recovered || strings.Contains(f, "panicked") }
	req := []byte("j\x81\xd20\x81ϡ\x03\x02\x01\x05\xa2\x03\x02\x01\n\xa3T0R0P\xa1\x03\x02\x01\x02\xa2\x0f\x04G0E\xa0\x03\x02\x01\x12\xa2>\x04< -\x81\x05G\t|\xcbW\xb0\x1eJ\xa6\xf0ͬOն\xfc\xb4$\x10*\xdc\xf7\x0e\x10\x04\x8c\a\xac\x89\x97A\x14Q{\xb7\x8110\xbb\x9e\xf6\xe4\xbf\xca\xfd\x94e\xa4b\xb7\xb8S\xb5\xa0⁤m0k\xa0\a\x03\x05\x00\x00\x01\x00\x00\xa1\x120\x10\xa0\x03\x02\x01\x00\xa1\t0\a\x1b\x05alice\xa2\f\x1b\nFLEET.TEST\xa3\x1f0\x1d\xa0\x03\x02\x01\x02\xa1\x160\x14\x1b\x06krbtgt\x1b\nFLEET.TEST\xa5\x11\x18\x0f20261101093655Z\xa7\x03\x02\x01*\xa8\x050\x00\x02\x01\xfa")
	if out := s.handle(req); len(out) != 0 {
		t.Errorf("answered a request the decoder cannot read, with %d bytes", len(out))
	}
	if !recovered {
		t.Error("the request no longer reaches the panicking decoder: the regression input needs refreshing")
	}
}

// FuzzHandle feeds arbitrary datagrams to the request dispatcher: whatever
// arrives, nothing may panic, and a reply is a KRB-ERROR or a ticket.
func FuzzHandle(f *testing.F) {
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	kt := keytab.New()
	for _, p := range []string{"krbtgt/" + testRealm, "nfs/localhost"} {
		if err := kt.AddEntry(p, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
			f.Fatal(err)
		}
	}
	s, err := New(Config{Realm: testRealm, People: onlyOne{id}, Services: kt})
	if err != nil {
		f.Fatal(err)
	}
	key, err := s.cfg.keyFor(id)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(asReqRealm(f, testRealm, nil))
	f.Add(asReqRealm(f, testRealm, timestampPA(f, key, time.Now())))
	n := now().UTC()
	tgtName := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	client := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	tkt, sk, err := messages.NewTicket(client, testRealm, tgtName, testRealm, types.NewKrbFlags(),
		kt, defaultEtype, 2, n, n, n.Add(time.Hour), time.Time{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(signedTGSReq(f, tkt, sk, client, messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		Till:  n.Add(time.Hour), Nonce: 7, EType: []int32{defaultEtype}}, bodyChecksum(f, sk)))
	var panicked atomic.Value
	s.cfg.Logf = func(format string, a ...any) {
		if strings.Contains(format, "panicked") {
			panicked.Store(fmt.Sprintf(format, a...))
		}
	}
	f.Add([]byte{0x6a, 0x03, 0x02, 0x01, 0x05})
	f.Add([]byte{0x6c, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxRequest {
			return
		}
		// handle recovers: a panic inside the third-party decoder costs one
		// request. What the fuzzer asserts is that none ESCAPES, and that a
		// reply, when there is one, is itself a decodable KRB-ERROR or
		// KDC-REP.
		out := s.handle(b)
		if p := panicked.Load(); p != nil {
			t.Log(p) // recovered: see TestADecoderPanicCostsOneRequest
		}
		if len(out) > 0 {
			var e messages.KRBError
			var r messages.ASRep
			var g messages.TGSRep
			if e.Unmarshal(out) != nil && r.Unmarshal(out) != nil && g.Unmarshal(out) != nil {
				t.Fatalf("a reply that is neither KRB-ERROR nor KDC-REP: %x", out)
			}
		}
	})
}
