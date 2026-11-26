package pac

import (
	"encoding/binary"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/types"
)

// allocated is the bytes fn allocates, measured with the collector's own
// counter: exact for a single goroutine.
func allocated(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// A count that the bytes left cannot hold, and a count past the bound, are
// refused BEFORE the slice is made: the refusal is the same error either way
// further down, so only the allocation tells the guard is there.
func TestGroupCountRefusedBeforeAllocation(t *testing.T) {
	conf := func(n uint32, size int) []byte {
		b := make([]byte, 4+size)
		binary.LittleEndian.PutUint32(b, n)
		return b
	}
	for name, c := range map[string]struct {
		n    uint32
		size int
	}{
		"bound, bytes present": {MaxGroupEntries + 1, 8 * (MaxGroupEntries + 1)},
		"bytes missing":        {MaxGroupEntries, 0},
		"bytes one short":      {MaxGroupEntries, 8*MaxGroupEntries - 1},
	} {
		r := &reader{b: conf(c.n, c.size)}
		var out []Group
		got := allocated(func() { out = r.groups(c.n, "GroupIds") })
		if r.err == nil || !errors.Is(r.err, ErrNDR) || len(out) != 0 {
			t.Errorf("%s: err %v, %d groups", name, r.err, len(out))
		}
		// TotalAlloc is the whole process's: a first call (lazy init of fmt,
		// the runtime's own background work) read 4856 bytes on linux/386
		// once. The guard's allocation is a property of every run, a stray
		// one is not, so the SMALLEST of five is the measure.
		for range 4 {
			r2 := &reader{b: conf(c.n, c.size)}
			got = min(got, allocated(func() { out = r2.groups(c.n, "GroupIds") }))
		}
		if got > 4096 {
			t.Errorf("%s: %d bytes allocated before the refusal", name, got)
		}
	}
	// Exactly the bytes needed is accepted.
	r := &reader{b: conf(3, 24)}
	if out := r.groups(3, "GroupIds"); r.err != nil || len(out) != 3 {
		t.Errorf("exact fit: %v %d", r.err, len(out))
	}
}

// resign recomputes the server and KDC signatures of a PAC whose other buffers
// were edited, so that the edit is the only thing that can fail.
func resign(t *testing.T, p *PAC, srv, kdc types.EncryptionKey) {
	t.Helper()
	b6 := sigOf(t, p, TypeServerChecksum)
	b7 := sigOf(t, p, TypeKDCChecksum)
	clear(b6[4:])
	clear(b7[4:])
	copy(b6[4:], checksum(srv, p.Raw))
	copy(b7[4:], checksum(kdc, b6[4:]))
}

func TestFullAndTicketSignaturesEachHeldAlone(t *testing.T) {
	srv, kdc := key(1), key(2)
	in := &Input{
		Logon: sampleLogon(t), ClientName: "alice", AuthTime: time.Unix(1700000000, 0),
		UPN: "alice@EXAMPLE.ORG", DNSDomain: "EXAMPLE.ORG", SamName: "alice",
		UserSID: mustSID(t, "S-1-5-21-111-222-333-1001"), RequestorSID: mustSID(t, "S-1-5-21-111-222-333-1001"),
		ServiceTicket: true, TicketBytes: []byte("ticket"),
	}
	for _, typ := range []uint32{TypeFullChecksum, TypeTicketChecksum} {
		b, err := build(in, srv, kdc)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		sigOf(t, p, typ)[10] ^= 1
		resign(t, p, srv, kdc)
		// Server and KDC signatures are now right: only 16 or 19 is wrong.
		if err := verify(p, srv, kdc, true, in.TicketBytes); !errors.Is(err, ErrSignature) {
			t.Errorf("a wrong signature of type %d: %v", typ, err)
		}
	}
}

// A key of the right length but another type is not an AES-256 key: the
// signature is refused for the key, not by luck of a mismatch.
func TestKeyTypeRefusedByVerify(t *testing.T) {
	srv, kdc := key(1), key(2)
	in := &Input{
		Logon: sampleLogon(t), ClientName: "alice", AuthTime: time.Unix(1700000000, 0),
		UPN: "alice@EXAMPLE.ORG", DNSDomain: "EXAMPLE.ORG", SamName: "alice",
		UserSID: mustSID(t, "S-1-5-21-111-222-333-1001"), RequestorSID: mustSID(t, "S-1-5-21-111-222-333-1001"),
	}
	b, err := build(in, srv, kdc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(p, srv, kdc, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ s, k types.EncryptionKey }{
		{types.EncryptionKey{KeyType: 17, KeyValue: srv.KeyValue}, kdc},
		{srv, types.EncryptionKey{KeyType: 23, KeyValue: kdc.KeyValue}},
	} {
		err := verify(p, c.s, c.k, false, nil)
		if !errors.Is(err, ErrSignature) || errors.Is(err, errPanicked) {
			t.Errorf("key types %d/%d: %v", c.s.KeyType, c.k.KeyType, err)
		}
	}
}
