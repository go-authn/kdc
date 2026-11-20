package kdc

import (
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// gokrb5Panics reports whether gokrb5 v8.4.4 panics decoding req as an AS-REQ
// or as a TGS-REQ: the two decoders serve tries.
func gokrb5Panics(req []byte) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	var as messages.ASReq
	_ = as.Unmarshal(req)
	var tgs messages.TGSReq
	_ = tgs.Unmarshal(req)
	return false
}

// kdcReq wraps a KDC-REQ-BODY's encoding, taken as is, in a KDC-REQ under
// appTag (10 AS-REQ, 12 TGS-REQ), so that a test can put bytes in the body that
// no encoder would.
func kdcReq(t *testing.T, appTag int, body []byte) []byte {
	t.Helper()
	msgType := 10
	if appTag == asnAppTag.TGSREQ {
		msgType = 12
	}
	// Built element by element: gofork writes a RawValue's FullBytes as they
	// are, without the explicit [4] around them.
	field := func(tag int, inner []byte) []byte {
		b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	integer := func(v int) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var seq []byte
	seq = append(seq, field(1, integer(5))...)
	seq = append(seq, field(2, integer(msgType))...)
	seq = append(seq, field(4, body)...)
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: seq})
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(b, appTag)
}

// withExtra appends raw elements at the end of a KDC-REQ-BODY SEQUENCE.
func withExtra(t *testing.T, body, extra []byte) []byte {
	t.Helper()
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(body, &seq); err != nil {
		t.Fatal(err)
	}
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte(nil), seq.Bytes...), extra...)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// What the guard refuses, and that it refuses nothing gokrb5 reads.
//
// The property that matters is one-sided: whatever the guard lets through
// must not panic gokrb5. The control rows are honest requests carrying one
// and two tickets, the way gokrb5's own client builds them for user-to-user,
// which must pass and decode.
func TestAdditionalTicketsGuard(t *testing.T) {
	kt := keytab.New()
	if err := kt.AddEntry("krbtgt/"+testRealm, testRealm, "a key nobody types", time.Now(), 2, 18); err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC()
	tgtName := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}
	client := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}
	tkt, _, err := messages.NewTicket(client, testRealm, tgtName, testRealm, types.NewKrbFlags(),
		kt, defaultEtype, 2, n, n, n.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	body := func(tickets ...messages.Ticket) []byte {
		kb := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm, SName: tgtName,
			Till: n.Add(time.Hour), Nonce: 7, EType: []int32{defaultEtype}, AdditionalTickets: tickets}
		b, err := kb.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	plain := body()

	for _, tc := range []struct {
		name    string
		body    []byte
		refused bool
		decodes bool // gokrb5 reads it without error (only asked of what passes)
	}{
		{"no additional tickets", plain, false, true},
		{"one ticket", body(tkt), false, true},
		{"two tickets", body(tkt, tkt), false, true},

		// The FuzzHandle shape: a one-byte INTEGER where [11] would be, which
		// gofork hands to the OPTIONAL RawValue. gokrb5 panics on it.
		{"a bare one-byte INTEGER after etype", withExtra(t, plain, []byte{0x02, 0x01, 0xfa}), true, false},
		// A SEQUENCE where [11] should be: harmless to gokrb5 (two bytes and
		// more), but not the field RFC 4120 defines, so it is not one.
		{"a bare SEQUENCE after etype", withExtra(t, plain, []byte{0x30, 0x02, 0x30, 0x00}), true, false},
		{"[11] holding an INTEGER", withExtra(t, plain, []byte{0xab, 0x03, 0x02, 0x01, 0xfa}), true, false},
		{"[11] holding a SEQUENCE and a trailing byte string",
			withExtra(t, plain, []byte{0xab, 0x05, 0x30, 0x00, 0x04, 0x01, 0x00}), true, false},
		{"[11] holding a SET", withExtra(t, plain, []byte{0xab, 0x02, 0x31, 0x00}), true, false},
		{"[11] holding a primitive SEQUENCE tag", withExtra(t, plain, []byte{0xab, 0x02, 0x10, 0x00}), true, false},

		// Right shape, wrong contents: passes the guard and gokrb5 refuses it
		// with an error, not a panic.
		{"[11] holding a SEQUENCE of a NULL", withExtra(t, plain, []byte{0xab, 0x04, 0x30, 0x02, 0x05, 0x00}), false, false},
	} {
		for _, app := range []int{asnAppTag.ASREQ, asnAppTag.TGSREQ} {
			req := kdcReq(t, app, tc.body)
			if got := additionalTicketsUnreadable(req); got != tc.refused {
				t.Errorf("%s (app %d): refused = %v, want %v", tc.name, app, got, tc.refused)
			}
			if tc.refused {
				continue
			}
			if gokrb5Panics(req) {
				t.Errorf("%s (app %d): the guard let through a request that panics gokrb5", tc.name, app)
				continue
			}
			var err error
			if app == asnAppTag.ASREQ {
				err = new(messages.ASReq).Unmarshal(req)
			} else {
				err = new(messages.TGSReq).Unmarshal(req)
			}
			if (err == nil) != tc.decodes {
				t.Errorf("%s (app %d): gokrb5 decode err = %v, want decodes = %v", tc.name, app, err, tc.decodes)
			}
		}
	}

	// The witness that the first malformed row is the live hazard, not a
	// hypothetical one.
	if !gokrb5Panics(kdcReq(t, asnAppTag.ASREQ, withExtra(t, plain, []byte{0x02, 0x01, 0xfa}))) {
		t.Error("gokrb5 no longer panics on a bare one-byte INTEGER after etype: re-read go-authn/kdc#28")
	}
}
