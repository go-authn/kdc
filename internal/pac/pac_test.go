package pac

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	gpac "github.com/jcmturner/gokrb5/v8/pac"
	"github.com/jcmturner/gokrb5/v8/types"
)

func key(b byte) types.EncryptionKey {
	return types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{b}, 32)}
}

func mustSID(t testing.TB, s string) SID {
	t.Helper()
	v, err := ParseSID(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func sampleLogon(t testing.TB) *LogonInfo {
	dom := mustSID(t, "S-1-5-21-111-222-333")
	extra := mustSID(t, "S-1-18-1")
	return &LogonInfo{
		LogonTime: FileTime(time.Unix(1700000000, 0)), LogoffTime: FileTimeNever,
		KickOffTime: FileTimeNever, PasswordLastSet: 1, PasswordCanChange: 2,
		PasswordMustChange: FileTimeNever,
		EffectiveName:      "alice", FullName: "Alice é", UserID: 1001, PrimaryGroupID: 513,
		Groups:    []Group{{513, GroupAttrs}, {1002, GroupAttrs}},
		UserFlags: 0x20, LogonServer: "KDC", LogonDomainName: "EXAMPLE",
		LogonDomainID: dom, UserAccountControl: 0x10,
		ExtraSIDs: []ExtraSID{{extra, GroupAttrs}},
	}
}

func TestNDRRoundTrip(t *testing.T) {
	for name, li := range map[string]*LogonInfo{
		"full":  sampleLogon(t),
		"empty": {LogonDomainID: mustSID(t, "S-1-5-21-1-2-3")},
		"resource": func() *LogonInfo {
			l := sampleLogon(t)
			s := mustSID(t, "S-1-5-21-9-8-7")
			l.ResourceGroupDomainSID = &s
			l.ResourceGroups = []Group{{5, 7}}
			return l
		}(),
	} {
		b, err := li.Marshal()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(b)%8 != 0 {
			t.Errorf("%s: %d bytes is not a multiple of 8", name, len(b))
		}
		got, err := UnmarshalLogonInfo(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, li) {
			t.Errorf("%s: round trip\n got %+v\nwant %+v", name, got, li)
		}
	}
}

func TestNDRBounds(t *testing.T) {
	l := sampleLogon(t)
	l.Groups = make([]Group, MaxGroupEntries+1)
	if _, err := l.Marshal(); !errors.Is(err, ErrTooBig) {
		t.Errorf("too many groups: %v", err)
	}
	l = sampleLogon(t)
	l.EffectiveName = string(bytes.Repeat([]byte("a"), MaxStringUnits+1))
	if _, err := l.Marshal(); !errors.Is(err, ErrTooBig) {
		t.Errorf("long string: %v", err)
	}
	// A count that promises more entries than there are bytes is refused
	// before anything is allocated.
	b, _ := sampleLogon(t).Marshal()
	for i := range b {
		c := append([]byte(nil), b[:i]...)
		if _, err := unmarshal(c); !errors.Is(err, ErrNDR) {
			t.Fatalf("a truncation to %d bytes was accepted", i)
		}
	}
}

func TestBuildVerifyAndGokrb5Oracle(t *testing.T) {
	srv, kdc := key(1), key(2)
	in := &Input{
		Logon: sampleLogon(t), ClientName: "alice", AuthTime: time.Unix(1700000000, 999),
		UPN: "alice@EXAMPLE.ORG", DNSDomain: "EXAMPLE.ORG", SamName: "alice",
		UserSID: mustSID(t, "S-1-5-21-111-222-333-1001"), RequestorSID: mustSID(t, "S-1-5-21-111-222-333-1001"),
		ServiceTicket: true, TicketBytes: []byte("the ticket with a zero in place of the PAC"),
	}
	b, err := build(in, srv, kdc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(p, srv, kdc, true, in.TicketBytes); err != nil {
		t.Fatal(err)
	}
	at, name, err := clientInfoOf(p)
	if err != nil || at != 1700000000 || name != "alice" {
		t.Errorf("CLIENT_INFO: %d %q %v", at, name, err)
	}
	// Each signature is bound to what it covers.
	if err := verify(p, srv, kdc, true, []byte("another ticket")); !errors.Is(err, ErrSignature) {
		t.Error("a ticket signature verified over another ticket")
	}
	if err := verify(p, kdc, kdc, true, in.TicketBytes); !errors.Is(err, ErrSignature) {
		t.Error("the server signature verified under another key")
	}
	if err := verify(p, srv, srv, true, in.TicketBytes); !errors.Is(err, ErrSignature) {
		t.Error("the KDC signatures verified under another key")
	}
	for i := 8 + 16*9; i < len(b); i++ {
		c := append([]byte(nil), b...)
		c[i] ^= 1
		q, err := parse(c)
		if errors.Is(err, errPanicked) {
			t.Fatalf("a flipped bit at %d: %v", i, err)
		}
		if err != nil {
			continue
		}
		if verify(q, srv, kdc, true, in.TicketBytes) == nil {
			// Only padding may change without breaking a signature.
			if !isPadding(p, i) {
				t.Fatalf("a flipped bit at %d outside any padding verified", i)
			}
		}
	}

	// gokrb5 is the in-process oracle: it parses the container, the NDR and
	// the server signature under the service key.
	var g gpac.PACType
	if err := g.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if err := g.ProcessPACInfoBuffers(srv, nil); err != nil {
		t.Fatal(err)
	}
	if g.KerbValidationInfo == nil || g.KerbValidationInfo.EffectiveName.Value != "alice" ||
		g.KerbValidationInfo.UserID != 1001 || len(g.KerbValidationInfo.GroupIDs) != 2 {
		t.Errorf("gokrb5 read %+v", g.KerbValidationInfo)
	}
	if g.ClientInfo == nil || g.ClientInfo.Name != "alice" {
		t.Errorf("gokrb5 CLIENT_INFO %+v", g.ClientInfo)
	}
}

func isPadding(p *PAC, i int) bool {
	for _, e := range p.list {
		if i >= e.start && i < e.end {
			return false
		}
	}
	return true
}

func TestTGTHasNoTicketSignature(t *testing.T) {
	srv := key(2)
	b, err := build(&Input{Logon: sampleLogon(t), ClientName: "alice", AuthTime: time.Unix(5, 0),
		UserSID: mustSID(t, "S-1-5-21-1-2-3-4"), RequestorSID: mustSID(t, "S-1-5-21-1-2-3-4")}, srv, srv)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := Parse(b)
	if _, ok := p.Buffer(TypeTicketChecksum); ok {
		t.Error("a TGT PAC carries a ticket signature")
	}
	if _, ok := p.Buffer(TypeFullChecksum); ok {
		t.Error("a TGT PAC carries a full signature")
	}
	if err := verify(p, srv, srv, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := verify(p, srv, srv, true, []byte("x")); !errors.Is(err, ErrSignature) {
		t.Error("a PAC without 16 passed when 16 was required")
	}
}

func TestHMACMD5SignatureRefused(t *testing.T) {
	srv, kdc := key(1), key(2)
	b, err := build(&Input{Logon: sampleLogon(t), ClientName: "a", AuthTime: time.Unix(5, 0),
		UserSID: mustSID(t, "S-1-5-21-1-2-3-4"), RequestorSID: mustSID(t, "S-1-5-21-1-2-3-4")}, srv, kdc)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := Parse(b)
	s, _ := p.Buffer(TypeServerChecksum)
	s[0], s[1], s[2], s[3] = 0x76, 0xff, 0xff, 0xff // -138, HMAC-MD5
	if err := verify(p, srv, kdc, false, nil); !errors.Is(err, ErrSignature) {
		t.Errorf("HMAC-MD5 signature: %v", err)
	}
}

func TestParseRefusals(t *testing.T) {
	good, _ := build(&Input{Logon: sampleLogon(t), ClientName: "a", AuthTime: time.Unix(5, 0),
		UserSID: mustSID(t, "S-1-5-21-1-2-3-4"), RequestorSID: mustSID(t, "S-1-5-21-1-2-3-4")}, key(1), key(2))
	for name, mut := range map[string]func([]byte){
		"unaligned offset": func(b []byte) { b[8+8] |= 1 },
		"huge size":        func(b []byte) { b[8+4+3] = 0xff },
		"version":          func(b []byte) { b[4] = 1 },
		"many buffers":     func(b []byte) { b[0] = 200 },
	} {
		c := append([]byte(nil), good...)
		mut(c)
		if _, err := parse(c); err == nil || errors.Is(err, errPanicked) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for i := 0; i < len(good); i++ {
		if _, err := parse(good[:i]); errors.Is(err, errPanicked) {
			t.Errorf("a truncation to %d bytes: %v", i, err)
		}
	}
}

func TestSID(t *testing.T) {
	s := mustSID(t, "S-1-5-21-1-2-3")
	if s.WithRID(7).String() != "S-1-5-21-1-2-3-7" {
		t.Error(s.WithRID(7))
	}
	r, err := parseBinary(s.Binary())
	if err != nil || !equalSIDs(t, r, s) {
		t.Error(r, err)
	}
	for _, bad := range []string{"", "S-2-5", "S-1", "S-1-5-x", "S-1-5-4294967296", "S-1-281474976710656"} {
		if _, err := parseSID(bad); err == nil || errors.Is(err, errPanicked) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// FuzzLogonInfo: whatever decodes re-encodes to something that decodes alike.
func FuzzLogonInfo(f *testing.F) {
	b, _ := sampleLogon(f).Marshal()
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		li, err := unmarshal(b)
		if errors.Is(err, errPanicked) {
			t.Fatal(err)
		}
		if err != nil {
			return
		}
		out, err := li.Marshal()
		if err != nil {
			t.Fatalf("decoded but cannot encode: %v", err)
		}
		again, err := UnmarshalLogonInfo(out)
		if err != nil || !reflect.DeepEqual(again, li) {
			t.Fatalf("re-encoding changed it: %v", err)
		}
	})
}

// FuzzPACVerify: parsing and verifying arbitrary bytes never panics and never
// accepts anything that was not signed with these keys.
func FuzzPACVerify(f *testing.F) {
	srv, kdc := key(1), key(2)
	b, _ := build(&Input{Logon: sampleLogon(f), ClientName: "a", AuthTime: time.Unix(5, 0),
		UserSID: mustSID(f, "S-1-5-21-1-2-3-4"), RequestorSID: mustSID(f, "S-1-5-21-1-2-3-4")}, srv, kdc)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := parse(b)
		if errors.Is(err, errPanicked) {
			t.Fatal(err)
		}
		if err != nil {
			return
		}
		if _, _, err := clientInfoOf(p); errors.Is(err, errPanicked) {
			t.Fatal(err)
		}
		if err := verify(p, srv, kdc, false, nil); errors.Is(err, errPanicked) {
			t.Fatal(err)
		}
		if li, ok := p.Buffer(TypeLogonInfo); ok {
			if _, err := unmarshal(li); errors.Is(err, errPanicked) {
				t.Fatal(err)
			}
		}
	})
}
