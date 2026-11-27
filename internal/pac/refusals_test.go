package pac

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/types"
)

// Offsets in the encoding of sampleLogon, fixed by the NDR layout.
const (
	offUserID     = 120
	offGroupCount = 128
	offGroupRef   = 132
	offDomainRef  = 172
	offSIDCount   = 216
	offSIDsRef    = 220
	offResSIDRef  = 224
	offResCount   = 228
	offResRef     = 232
	offHead0      = 68  // EffectiveName: length, max, ref
	offBody0      = 236 // its deferred buffer: max, offset, actual
)

func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func put16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }

func sample(t *testing.T) []byte {
	t.Helper()
	b, err := sampleLogon(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(b[offUserID:]) != 1001 || binary.LittleEndian.Uint32(b[offBody0+8:]) != 5 {
		t.Fatal("the layout constants of this test no longer match the encoding")
	}
	return b
}

func TestNDRRefusals(t *testing.T) {
	for name, mut := range map[string]func([]byte) []byte{
		"header":            func(b []byte) []byte { b[0] = 2; return b },
		"filler":            func(b []byte) []byte { b[12] = 1; return b },
		"object length":     func(b []byte) []byte { b[8] += 8; return b },
		"null top":          func(b []byte) []byte { put32(b, 16, 0); return b },
		"odd length":        func(b []byte) []byte { put16(b, offHead0, 9); return b },
		"odd maximum":       func(b []byte) []byte { put16(b, offHead0+2, 11); return b },
		"length over max":   func(b []byte) []byte { put16(b, offHead0+2, 8); return b },
		"string too long":   func(b []byte) []byte { put16(b, offHead0, 0xfffe); put16(b, offHead0+2, 0xfffe); return b },
		"null with length":  func(b []byte) []byte { put32(b, offHead0+4, 0); return b },
		"max over bound":    func(b []byte) []byte { put32(b, offBody0, 5000); return b },
		"offset not zero":   func(b []byte) []byte { put32(b, offBody0, 6); put32(b, offBody0+4, 1); return b },
		"actual over max":   func(b []byte) []byte { put32(b, offBody0, 4); return b },
		"actual not length": func(b []byte) []byte { put32(b, offBody0+8, 4); return b },
		"null domain":       func(b []byte) []byte { put32(b, offDomainRef, 0); return b },
		"groups no pointer": func(b []byte) []byte { put32(b, offGroupRef, 0); return b },
		"groups count":      func(b []byte) []byte { put32(b, offGroupCount, 3); return b },
		"sids no pointer":   func(b []byte) []byte { put32(b, offSIDsRef, 0); return b },
		"sids count":        func(b []byte) []byte { put32(b, offSIDCount, 2); return b },
		"res no pointer":    func(b []byte) []byte { put32(b, offResCount, 1); return b },
		"too big":           func(b []byte) []byte { return append(b, make([]byte, MaxLogonInfo)...) },
		"short":             func(b []byte) []byte { return b[:19] },
	} {
		if _, err := unmarshal(mut(sample(t))); !errors.Is(err, ErrNDR) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The group count promises more entries than the buffer holds, or more than
// the bound: refused before anything is allocated.
func TestNDRCountsAreBoundedBeforeAllocation(t *testing.T) {
	b := sample(t)
	groupsAt := -1
	for i := offBody0; i+4 <= len(b); i += 4 { // the GroupIds conformance: 2, then 513 7
		if binary.LittleEndian.Uint32(b[i:]) == 2 && binary.LittleEndian.Uint32(b[i+4:]) == 513 {
			groupsAt = i
			break
		}
	}
	if groupsAt < 0 {
		t.Fatal("GroupIds not found")
	}
	for name, n := range map[string]uint32{"more than the bytes": 1000, "over the bound": MaxGroupEntries + 1} {
		// Counts of 2^29 and 2^32-1 are not tried here: with the guard removed
		// they would allocate gigabytes. TestGroupCountRefusedBeforeAllocation
		// measures the allocation at the bound instead.
		c := append([]byte(nil), b...)
		put32(c, offGroupCount, n)
		put32(c, groupsAt, n)
		if _, err := unmarshal(c); !errors.Is(err, ErrNDR) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c := append([]byte(nil), b...)
	put32(c, groupsAt, 3) // conformance differs from the count
	if _, err := unmarshal(c); !errors.Is(err, ErrNDR) {
		t.Errorf("conformance: %v", err)
	}
}

func TestNDRSIDRefusals(t *testing.T) {
	b := sample(t)
	at := -1
	for i := offBody0; i+8 <= len(b); i += 4 { // LogonDomainId: conformance 4, S-1-5-21-...
		if binary.LittleEndian.Uint32(b[i:]) == 4 && b[i+4] == 1 && b[i+5] == 4 {
			at = i
			break
		}
	}
	if at < 0 {
		t.Fatal("LogonDomainId not found")
	}
	for name, mut := range map[string]func([]byte){
		"revision":     func(c []byte) { c[at+4] = 2 },
		"count":        func(c []byte) { c[at+5] = 3 },
		"over fifteen": func(c []byte) { put32(c, at, 16) },
		"enormous":     func(c []byte) { put32(c, at, 0xffffffff) },
		"wraps":        func(c []byte) { put32(c, at, 1<<30) },
		"truncated":    func(c []byte) { put32(c, at, 15); c[at+5] = 15 },
	} {
		c := append([]byte(nil), b...)
		mut(c)
		if _, err := unmarshal(c); !errors.Is(err, ErrNDR) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNDRNullEmptyStringAndEmptyGroups(t *testing.T) {
	l := &LogonInfo{LogonDomainID: mustSID(t, "S-1-5-21-1-2-3")}
	b, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(b[offHead0+4:]) != 0 {
		t.Error("an empty string is not written as a null pointer")
	}
	got, err := unmarshal(b)
	if err != nil || got.EffectiveName != "" || len(got.Groups) != 0 {
		t.Fatal(got, err)
	}
	// And a non-empty one is a non-null pointer.
	if binary.LittleEndian.Uint32(sample(t)[offHead0+4:]) == 0 {
		t.Error("a string is written as a null pointer")
	}
}

func TestBuildRefusals(t *testing.T) {
	ok := func() *Input {
		return &Input{Logon: sampleLogon(t), ClientName: "a", AuthTime: time.Unix(5, 0),
			UserSID: mustSID(t, "S-1-5-21-1-2-3-4"), RequestorSID: mustSID(t, "S-1-5-21-1-2-3-4"),
			TicketBytes: []byte("t")}
	}
	bad := types.EncryptionKey{KeyType: 17, KeyValue: make([]byte, 16)}
	if _, err := build(&Input{}, key(1), key(2)); !errors.Is(err, ErrPAC) {
		t.Errorf("no logon: %v", err)
	}
	in := ok()
	in.Logon.Groups = make([]Group, MaxGroupEntries+1)
	if _, err := build(in, key(1), key(2)); !errors.Is(err, ErrTooBig) {
		t.Errorf("logon too big: %v", err)
	}
	for _, svc := range []bool{false, true} {
		for name, keys := range map[string][2]types.EncryptionKey{
			"server key": {bad, key(2)}, "kdc key": {key(1), bad},
		} {
			in := ok()
			in.ServiceTicket = svc
			if _, err := build(in, keys[0], keys[1]); !errors.Is(err, ErrSignature) {
				t.Errorf("%s, service=%v: %v", name, svc, err)
			}
		}
	}
	// A key is AES-256 by type AND by length.
	if _, err := build(ok(), types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 16)}, key(2)); !errors.Is(err, ErrSignature) {
		t.Errorf("short key: %v", err)
	}
	if _, err := build(ok(), key(1), types.EncryptionKey{KeyType: 17, KeyValue: make([]byte, 32)}); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong type: %v", err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	srv, kdc := key(1), key(2)
	tb := []byte("ticket")
	good, err := build(&Input{Logon: sampleLogon(t), ClientName: "alice", AuthTime: time.Unix(5, 0),
		UserSID: mustSID(t, "S-1-5-21-1-2-3-4"), RequestorSID: mustSID(t, "S-1-5-21-1-2-3-4"),
		ServiceTicket: true, TicketBytes: tb}, srv, kdc)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := parse(good); verify(p, srv, kdc, true, tb) != nil {
		t.Fatal("the control does not verify")
	}
	// Header entries, in order: 1 10 12 16 19 6 7.
	idx := map[uint32]int{TypeTicketChecksum: 3, TypeFullChecksum: 4, TypeServerChecksum: 5, TypeKDCChecksum: 6}
	for typ, i := range idx {
		e := 8 + 16*i
		for name, mut := range map[string]func([]byte){
			"missing":     func(b []byte) { put32(b, e, 99) },
			"short":       func(b []byte) { put32(b, e+4, 15) },
			"long":        func(b []byte) { put32(b, e+4, 17) },
			"HMAC-MD5":    func(b []byte) { off := binary.LittleEndian.Uint32(b[e+8:]); put32(b, int(off), 0xffffff76) },
			"bad content": func(b []byte) { off := binary.LittleEndian.Uint32(b[e+8:]); b[off+8] ^= 1 },
		} {
			c := append([]byte(nil), good...)
			mut(c)
			p, err := parse(c)
			if err != nil { // a size past the end of the PAC is refused by Parse
				if !errors.Is(err, ErrPAC) {
					t.Errorf("%d %s: %v", typ, name, err)
				}
				continue
			}
			if err := verify(p, srv, kdc, true, tb); !errors.Is(err, ErrSignature) {
				t.Errorf("buffer %d %s: %v", typ, name, err)
			}
		}
	}
	p, _ := parse(good)
	bad := types.EncryptionKey{KeyType: 17}
	if err := verify(p, bad, kdc, true, tb); !errors.Is(err, ErrSignature) {
		t.Errorf("bad server key: %v", err)
	}
	if err := verify(p, srv, bad, true, tb); !errors.Is(err, ErrSignature) {
		t.Errorf("bad kdc key: %v", err)
	}
}

func TestParseDuplicateAndStructure(t *testing.T) {
	good, _ := build(&Input{Logon: sampleLogon(t), ClientName: "a", AuthTime: time.Unix(5, 0),
		UserSID: mustSID(t, "S-1-5-21-1-2-3-4"), RequestorSID: mustSID(t, "S-1-5-21-1-2-3-4")}, key(1), key(2))
	c := append([]byte(nil), good...)
	put32(c, 8+16, TypeLogonInfo) // the second entry now repeats the first
	if _, err := parse(c); !errors.Is(err, ErrPAC) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := parse(good[:7]); !errors.Is(err, ErrPAC) {
		t.Errorf("short: %v", err)
	}
	if _, err := parse(make([]byte, MaxPAC+1)); !errors.Is(err, ErrPAC) {
		t.Errorf("long: %v", err)
	}
	c = append([]byte(nil), good[:8+16*3]...) // header promising more than there is
	put32(c, 0, 4)
	if _, err := parse(c); !errors.Is(err, ErrPAC) {
		t.Errorf("header over length: %v", err)
	}
	if _, ok := mustParse(t, good).Buffer(99); ok {
		t.Error("an absent buffer was found")
	}
}

func mustParse(t *testing.T, b []byte) *PAC {
	t.Helper()
	p, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClientInfoRefusals(t *testing.T) {
	mk := func(data []byte) *PAC {
		return layout([]buf{{TypeClientInfo, data}})
	}
	if _, _, err := clientInfoOf(layout([]buf{{TypeLogonInfo, []byte{1}}})); !errors.Is(err, ErrPAC) {
		t.Errorf("absent: %v", err)
	}
	if _, _, err := clientInfoOf(mk(make([]byte, 9))); !errors.Is(err, ErrPAC) {
		t.Errorf("short: %v", err)
	}
	odd := make([]byte, 13)
	odd[8] = 3
	if _, _, err := clientInfoOf(mk(odd)); !errors.Is(err, ErrPAC) {
		t.Errorf("odd: %v", err)
	}
	long := make([]byte, 12)
	long[8] = 4
	if _, _, err := clientInfoOf(mk(long)); !errors.Is(err, ErrPAC) {
		t.Errorf("past the buffer: %v", err)
	}
	ten := make([]byte, 10) // a zero-length name in exactly 10 bytes is fine
	if _, name, err := clientInfoOf(mk(ten)); err != nil || name != "" {
		t.Errorf("empty name: %q %v", name, err)
	}
	exact := append(make([]byte, 8), 2, 0, 'x', 0)
	if _, name, err := clientInfoOf(mk(exact)); err != nil || name != "x" {
		t.Errorf("exact fit: %q %v", name, err)
	}
}

func TestSIDRefusals(t *testing.T) {
	s := mustSID(t, "S-1-5-21-1-2-3")
	if equalSIDs(t, s, mustSID(t, "S-1-5-21-1-2")) || equalSIDs(t, mustSID(t, "S-1-5-21-1-2"), s) ||
		equalSIDs(t, s, mustSID(t, "S-1-5-21-1-2-4")) || equalSIDs(t, s, mustSID(t, "S-1-6-21-1-2-3")) {
		t.Error("different SIDs compared equal")
	}
	if !equalSIDs(t, s, mustSID(t, "S-1-5-21-1-2-3")) {
		t.Error("equal SIDs differ")
	}
	long := "S-1-5"
	for i := 0; i < MaxSubAuthorities; i++ {
		long += "-1"
	}
	if _, err := parseSID(long); err != nil {
		t.Errorf("fifteen sub-authorities: %v", err)
	}
	if _, err := parseSID(long + "-1"); !errors.Is(err, ErrBadSID) {
		t.Errorf("sixteen sub-authorities: %v", err)
	}
	for _, bad := range []string{"", "S", "S-1", "S-1-5-x", "X-1-5", "S-2-5", "S-1-" + "281474976710656", "S-1-5-4294967296"} {
		if _, err := parseSID(bad); !errors.Is(err, ErrBadSID) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	good := s.Binary()
	for name, b := range map[string][]byte{
		"short":    good[:7],
		"revision": append([]byte{2}, good[1:]...),
		"count":    append(append([]byte(nil), good[:1]...), append([]byte{16}, good[2:]...)...),
		"length":   good[:len(good)-1],
	} {
		if _, err := parseBinary(b); !errors.Is(err, ErrBadSID) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Fifteen is the most a binary SID may count; sixteen is refused by the
	// count even when the bytes are there.
	b16 := make([]byte, 8+4*16)
	b16[0], b16[1] = 1, 16
	if _, err := parseBinary(b16); !errors.Is(err, ErrBadSID) {
		t.Errorf("sixteen binary: %v", err)
	}
	b15 := make([]byte, 8+4*15)
	b15[0], b15[1] = 1, 15
	if _, err := parseBinary(b15); err != nil {
		t.Errorf("fifteen binary: %v", err)
	}
}

func TestMarshalSIDOverFifteen(t *testing.T) {
	l := sampleLogon(t)
	l.LogonDomainID = SID{Authority: 5, Sub: make([]uint32, MaxSubAuthorities+1)}
	if _, err := l.Marshal(); !errors.Is(err, ErrTooBig) {
		t.Error(err)
	}
	l = sampleLogon(t)
	l.ExtraSIDs = make([]ExtraSID, 2000)
	for i := range l.ExtraSIDs {
		l.ExtraSIDs[i].SID = SID{Authority: 5, Sub: make([]uint32, MaxSubAuthorities)}
	}
	l.Groups = make([]Group, MaxGroupEntries)
	l.ResourceGroups = make([]Group, MaxGroupEntries)
	for i := 0; i < 8; i++ { // push past MaxLogonInfo with long strings' worth of SIDs
		l.ExtraSIDs = append(l.ExtraSIDs, l.ExtraSIDs...)
		if len(l.ExtraSIDs) > MaxGroupEntries {
			l.ExtraSIDs = l.ExtraSIDs[:MaxGroupEntries]
			break
		}
	}
	// 4096 x (8+68) + 2 x 4096 x 8 is 376 KB: under the bound, so this encodes.
	if b, err := l.Marshal(); err != nil || len(b) > MaxLogonInfo {
		t.Errorf("a maximal logon info: %d bytes, %v", len(b), err)
	}
}
