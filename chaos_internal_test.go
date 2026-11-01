// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
)

// Chaos: framing errors, truncated and hostile peers, a clock that jumps and a
// server closed while it is busy. After all of it a well-formed request is
// still answered.
func TestChaosFramingAndClock(t *testing.T) {
	id := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, id)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.ServeTCP(ln) }()
	go func() { defer wg.Done(); s.ServeUDP(pc) }()

	good := asReqRealm(t, testRealm, nil)
	frame := func(b []byte) []byte {
		h := make([]byte, 4, 4+len(b))
		binary.BigEndian.PutUint32(h, uint32(len(b)))
		return append(h, b...)
	}
	for name, raw := range map[string][]byte{
		"length only, no body":      {0, 0, 1, 0},
		"two bytes of a length":     {0, 0},
		"reserved bit set":          {0x80, 0, 0, 5, 1, 2, 3, 4, 5},
		"length beyond the cap":     {0, 0x10, 0, 0},
		"body shorter than length":  frame(good)[:10],
		"zero length":               {0, 0, 0, 0},
		"garbage of declared size":  frame([]byte("not kerberos at all")),
		"valid, then half a second": append(frame(good), 0, 0, 1),
	} {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Write(raw)
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		io.Copy(io.Discard, c)
		c.Close()
		_ = name
	}
	// UDP: empty, one byte, and a datagram of noise.
	uc, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	uc.Write(nil)
	uc.Write([]byte{0x6a})
	uc.Write(make([]byte, 1500))

	// Still served, over both transports.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Write(frame(good))
	var hdr [4]byte
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatalf("no reply over TCP after the abuse: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	if got := errorCode(t, body); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Errorf("code %d, want PREAUTH_REQUIRED", got)
	}
	c.Close()
	uc.Write(good)
	buf := make([]byte, 4096)
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatalf("no reply over UDP after the abuse: %v", err)
	}
	if got := errorCode(t, buf[:n]); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Errorf("udp code %d, want PREAUTH_REQUIRED", got)
	}
	uc.Close()

	// A clock stepped by an hour in each direction: a fresh timestamp is then
	// outside the skew, and the answer says so rather than succeeding.
	key, _ := s.cfg.keyFor(id)
	orig := now
	defer func() { now = orig }()
	for _, step := range []time.Duration{time.Hour, -time.Hour} {
		now = func() time.Time { return orig().Add(step) }
		out := s.handle(asReqRealm(t, testRealm, timestampPA(t, key, orig())))
		if got := errorCode(t, out); got != errorcode.KDC_ERR_PREAUTH_FAILED {
			t.Errorf("clock %v off: code %d, want PREAUTH_FAILED", step, got)
		}
	}
	now = orig

	// Closing under load returns, and the serve loops end.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}
