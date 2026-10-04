package kdc

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-authn/directory"
)

// ⛔ A connection that sends part of a message and goes silent is closed when
// tcpIdle runs out, rather than holding a goroutine and a descriptor for as
// long as the peer likes (security audit: idle for 3 s, then still served).
func TestAConnectionThatStallsIsClosed(t *testing.T) {
	defer func(d time.Duration) { tcpIdle = d }(tcpIdle)
	tcpIdle = 200 * time.Millisecond
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeTCP(ln)
	defer s.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x00, 0x00}); err != nil { // half a length
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("a stalled connection was not closed: read gave %v", err)
	}

	// A request that arrives in time is still answered.
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	req := asReq(t, "alice", []string{"krbtgt", testRealm}, nil)
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(req)))
	if _, err := c2.Write(append(lp[:], req...)); err != nil {
		t.Fatal(err)
	}
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c2, lp[:]); err != nil {
		t.Fatalf("a prompt request was not answered: %v", err)
	}
}

// ⛔ Connections past maxTCPConns are closed on accept, so idle peers cannot
// take every descriptor; one freed is a place for the next.
func TestConnectionsPastTheCapAreClosed(t *testing.T) {
	defer func(n int) { maxTCPConns = n }(maxTCPConns)
	maxTCPConns = 2
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeTCP(ln)
	defer s.Close()

	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		held = append(held, c)
	}
	// Wait until both are registered, so the third is the one over the cap.
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections registered, want 2", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	extra, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("a connection past the cap was not closed: read gave %v", err)
	}
	_ = held
}

// ⛔ Datagrams past maxUDPWorkers are dropped, not each given a goroutine.
// With no worker free, nothing is answered; with one, the request is.
func TestDatagramsPastTheWorkerCapAreDropped(t *testing.T) {
	defer func(n int) { maxUDPWorkers = n }(maxUDPWorkers)
	maxUDPWorkers = 0
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeUDP(pc)
	defer s.Close()

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(asReq(t, "alice", []string{"krbtgt", testRealm}, nil)); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(make([]byte, 4096)); err == nil {
		t.Fatalf("with no worker free, %d bytes were answered", n)
	}
}
