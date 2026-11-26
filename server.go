package kdc

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Server answers Kerberos requests for one realm.
//
// The zero value is not usable; use [New].
type Server struct {
	cfg       Config
	lookaside *lookaside

	pacOnce sync.Once
	pacSt   *pacState

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	// perPeer counts the connections in conns by peerKey.
	perPeer map[string]int
	pc      net.PacketConn
	ln      net.Listener
	wg      sync.WaitGroup
}

// New checks a configuration and returns a server for it.
//
// It refuses a realm it could not serve -- no realm, no directory, no keytab,
// a keytab without the krbtgt key -- rather than starting and failing at the
// first kinit, where the error reaches a person who cannot fix it. A person
// whose source holds no password (a verifier) is refused per request, with
// KDC_ERR_NULL_KEY: whether a source holds passwords is known only per person.
func New(cfg Config) (*Server, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, lookaside: newLookaside(), conns: make(map[net.Conn]struct{}), perPeer: make(map[string]int)}, nil
}

// peerKey names the source a connection is counted against: its IP address,
// and for IPv6 its /64, which is what one subscriber is given and so what one
// host can rotate through freely. An address that is not TCP (a test's pipe)
// is its own string.
func peerKey(a net.Addr) string {
	if a == nil {
		return ""
	}
	t, ok := a.(*net.TCPAddr)
	if !ok {
		return a.String()
	}
	if t == nil {
		return ""
	}
	if v4 := t.IP.To4(); v4 != nil {
		return v4.String()
	}
	return t.IP.Mask(net.CIDRMask(64, 128)).String()
}

// peerCount is the number of connections held by one peerKey.
func (s *Server) peerCount(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.perPeer[key]
}

// maxRequest caps one request. RFC 4120 puts no limit on a KDC-REQ, but a
// realm's are small and a client that sends more is not asking for a ticket.
const maxRequest = 1 << 16

// ⛔ Limits on what an unauthenticated peer can hold (security audit: a
// connection that sent two bytes of its length and went silent held a
// goroutine and a descriptor forever, and so did a few thousand of them).
// Variables so that a test can shorten them; nothing outside the package sets
// them.
var (
	// tcpIdle is how long one message may take to arrive, its length
	// included, and how long a reply may take to be written. A realm's
	// requests arrive in milliseconds.
	tcpIdle = 30 * time.Second
	// maxTCPConns bounds the connections served at once. One more is closed
	// as soon as it is accepted; a client then retries, as it would on any
	// refused connection.
	maxTCPConns = 256
	// maxTCPPerIP bounds the connections one source address (one /64 for
	// IPv6) holds at once. Without it a single host takes every slot above
	// and keeps them for tcpIdle, which starves every other client: the
	// listener does not block, but nobody else is served.
	maxTCPPerIP = 16
	// maxUDPWorkers bounds the datagrams answered at once. One more is
	// dropped, which UDP allows and every client handles: it resends, or
	// falls back to TCP.
	maxUDPWorkers = 64
)

// ErrClosed is returned by ServeUDP and ServeTCP after Close.
var ErrClosed = errors.New("kdc: server closed")

// ServeUDP answers datagrams. It is the transport a client tries first: MIT's
// kinit sends UDP and falls back to TCP only when the reply does not fit or
// the KDC says so.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.pc = pc
	s.mu.Unlock()

	buf := make([]byte, maxRequest)
	workers := make(chan struct{}, maxUDPWorkers)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.isClosed() {
				return ErrClosed
			}
			return err
		}
		// A copy, because the next ReadFrom reuses the buffer and the reply
		// is built from what was read.
		select {
		case workers <- struct{}{}:
		default:
			continue // every worker busy: dropped, and the client resends
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		// Add under the lock Close takes before Wait: an Add racing a
		// Wait on a zero counter is a WaitGroup misuse.
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-workers
			return ErrClosed
		}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer func() { <-workers; s.wg.Done() }()
			if out := s.udpReply(s.handle(req)); len(out) > 0 {
				pc.WriteTo(out, addr)
			}
		}()
	}
}

// maxUDPReply is the largest reply sent in a datagram. A bigger one would be
// fragmented, and a fragmented reply to a spoofed source is an amplifier.
// 1465 is a choice, not a standard: it keeps a PAC of a few dozen groups on
// UDP and sends the rest to TCP. A variable so a test can move it.
var maxUDPReply = 1465

// udpReply is the reply as a datagram carries it. RFC 4120 7.2.1: a reply
// that does not fit is replaced by KRB_ERR_RESPONSE_TOO_BIG (52), and the
// client repeats the request over TCP. The lookaside (replay.go) still holds
// the full reply, so the TCP request costs no second PAC. The error is a few
// dozen bytes and answers a request that was already answered, so it reflects
// no more than the other refusals do.
func (s *Server) udpReply(out []byte) []byte {
	if len(out) <= maxUDPReply {
		return out
	}
	krbtgt := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", s.cfg.Realm}}
	return s.krbErr(krbtgt, errorcode.KRB_ERR_RESPONSE_TOO_BIG, "the reply does not fit a datagram: use TCP", nil)
}

// ServeTCP answers connections. Each carries a four-byte length in front of
// every message, which UDP does not (RFC 4120 §7.2.2).
func (s *Server) ServeTCP(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.ln = ln
	s.mu.Unlock()

	for {
		c, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return ErrClosed
			}
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return ErrClosed
		}
		peer := peerKey(c.RemoteAddr())
		if len(s.conns) >= maxTCPConns || s.perPeer[peer] >= maxTCPPerIP {
			s.mu.Unlock()
			c.Close()
			continue
		}
		s.conns[c] = struct{}{}
		s.perPeer[peer]++
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			s.serveConn(c)
		}()
	}
}

func (s *Server) serveConn(c net.Conn) {
	defer func() {
		c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		peer := peerKey(c.RemoteAddr())
		if s.perPeer[peer]--; s.perPeer[peer] <= 0 {
			delete(s.perPeer, peer)
		}
		s.mu.Unlock()
	}()
	for {
		// One deadline for the whole message, length included: a peer that
		// trickles a byte at a time does not reset it.
		if err := c.SetReadDeadline(time.Now().Add(tcpIdle)); err != nil {
			return
		}
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		// The high bit is reserved and MUST be zero (RFC 4120 §7.2.2). A
		// client that sets it is not speaking this protocol, and masking it
		// off would read a length nobody sent.
		n := binary.BigEndian.Uint32(hdr[:])
		if n&0x8000_0000 != 0 || n > maxRequest {
			return
		}
		req := make([]byte, n)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		out := s.handle(req)
		if len(out) == 0 {
			return
		}
		var olen [4]byte
		binary.BigEndian.PutUint32(olen[:], uint32(len(out)))
		if err := c.SetWriteDeadline(time.Now().Add(tcpIdle)); err != nil {
			return
		}
		if _, err := c.Write(append(olen[:], out...)); err != nil {
			return
		}
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close stops the server and drops what it is serving.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	pc, ln, conns := s.pc, s.ln, s.conns
	s.conns = nil
	s.mu.Unlock()

	if pc != nil {
		pc.Close()
	}
	if ln != nil {
		ln.Close()
	}
	for c := range conns {
		c.Close()
	}
	s.wg.Wait()
	return nil
}
