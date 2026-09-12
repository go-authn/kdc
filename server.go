package kdc

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// Server answers Kerberos requests for one realm.
//
// The zero value is not usable; use [New].
type Server struct {
	cfg Config

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	pc     net.PacketConn
	ln     net.Listener
	wg     sync.WaitGroup
}

// New checks a configuration and returns a server for it.
//
// It refuses a realm it could not serve — no keytab, no krbtgt key, a
// directory that publishes no passwords — rather than starting and failing at
// the first kinit, where the error reaches a person who cannot fix it.
func New(cfg Config) (*Server, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, conns: make(map[net.Conn]struct{})}, nil
}

// maxRequest caps one request. RFC 4120 puts no limit on a KDC-REQ, but a
// realm's are small and a client that sends more is not asking for a ticket.
const maxRequest = 1 << 16

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
		req := make([]byte, n)
		copy(req, buf[:n])
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if out := s.handle(req); len(out) > 0 {
				pc.WriteTo(out, addr)
			}
		}()
	}
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
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
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
		s.mu.Unlock()
	}()
	for {
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
