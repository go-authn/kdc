package kdc

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-authn/directory"
)

// Suspicion 5. The listener does not block when maxTCPConns is reached (the
// connection is closed on accept and the loop goes on), but ONE address could
// still take every slot for tcpIdle and so starve every other client. Each
// source address is limited to maxTCPPerIP of them.
func TestOneAddressCannotTakeEverySlot(t *testing.T) {
	defer func(n, p int) { maxTCPConns, maxTCPPerIP = n, p }(maxTCPConns, maxTCPPerIP)
	maxTCPConns, maxTCPPerIP = 8, 2
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeTCP(ln)
	defer s.Close()

	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	waitConns(t, s, 2)
	third, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	third.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := third.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("a third connection from one address, with 5 slots free, was not closed: %v", err)
	}
}

// A slot is given back when its connection ends, so the limit is not a
// ratchet.
func TestAClosedConnectionGivesItsSlotBack(t *testing.T) {
	defer func(n, p int) { maxTCPConns, maxTCPPerIP = n, p }(maxTCPConns, maxTCPPerIP)
	maxTCPConns, maxTCPPerIP = 8, 1
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeTCP(ln)
	defer s.Close()

	for round := 0; round < 3; round++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		waitConns(t, s, 1)
		c.Close()
		waitConns(t, s, 0)
		if n := s.peerCount("127.0.0.1"); n != 0 {
			t.Fatalf("round %d: %d slots still held by a closed connection", round, n)
		}
	}
}

func TestPeerKeyGroupsAnIPv6Prefix(t *testing.T) {
	a := peerKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1")})
	b := peerKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff::9")})
	c := peerKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1")})
	if a != b {
		t.Errorf("one /64 gives two keys: %q %q", a, b)
	}
	if a == c {
		t.Errorf("two /64s give one key: %q", a)
	}
	if k := peerKey(&net.TCPAddr{IP: net.ParseIP("192.0.2.7")}); k != "192.0.2.7" {
		t.Errorf("IPv4 key = %q", k)
	}
	if k := peerKey(&net.UnixAddr{Name: "x", Net: "unix"}); k != "x" {
		t.Errorf("non-TCP key = %q", k)
	}
	if k := peerKey(nil); k != "" {
		t.Errorf("nil address key = %q", k)
	}
	var none *net.TCPAddr
	if k := peerKey(none); k != "" {
		t.Errorf("nil *TCPAddr key = %q", k)
	}
}

func waitConns(t *testing.T, s *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections registered, want %d", n, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
