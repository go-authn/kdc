package kdc

import (
	"encoding/binary"
	"io"
	"net/http"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
)

// KKDCP: Kerberos over HTTPS, [MS-KKDCP] (Microsoft Open Specifications,
// "Kerberos Key Distribution Center (KDC) Proxy Protocol"), which is what
// Windows' KdcProxy policy and MIT krb5's `kdc = https://host/KdcProxy` speak
// (MIT: src/lib/krb5/os/sendto_kdc.c, make_proxy_request and
// service_https_read). A client POSTs a KDC-PROXY-MESSAGE, the proxy hands the
// Kerberos message inside to the KDC, and answers with the KDC's reply in the
// same envelope. Here the "KDC" is this process: the request goes to the same
// dispatcher as a datagram on UDP 88 or a message on TCP 88, so a reply is the
// reply the other transports give, lookaside included (replay.go).
//
// The envelope (section 2.2.2):
//
//	KDC-PROXY-MESSAGE ::= SEQUENCE {
//	    kerb-message   [0] OCTET STRING,   -- the message WITH its 4-octet length (RFC 4120 7.2.2)
//	    target-domain  [1] KERB-REALM OPTIONAL,
//	    dclocator-hint [2] INTEGER OPTIONAL
//	}
//
// target-domain is required of a client message and not used in a server's;
// dclocator-hint only helps a proxy that must LOCATE a domain controller
// (section 3.2.5.1, DsrGetDcNameEx2), which this one is, so it is read and
// ignored.

// kkdcpMaxBody bounds the HTTP body: a request (maxRequest) plus its length,
// the envelope's tags and a realm name, with room to spare.
const kkdcpMaxBody = maxRequest + 4 + 1024

// proxyMessage is KDC-PROXY-MESSAGE. The tags are EXPLICIT (the module in
// [MS-KKDCP] is EXPLICIT TAGS), and KERB-REALM is a GeneralString.
type proxyMessage struct {
	KerbMessage   []byte `asn1:"explicit,tag:0"`
	TargetDomain  string `asn1:"explicit,tag:1,optional,generalstring"`
	DCLocatorHint int    `asn1:"explicit,tag:2,optional"`
}

// KKDCPHandler is the HTTP face of the realm for [MS-KKDCP]: POST a
// KDC-PROXY-MESSAGE, receive the KDC's reply in one. It is meant to sit behind
// a reverse proxy that terminates TLS (Windows requires HTTPS), on a path such
// as /KdcProxy, which is where both clients look by default.
//
// It refuses what it cannot answer instead of guessing:
//
//   - any method but POST: 405;
//   - a body over the bound: 413;
//   - bytes that are not exactly one KDC-PROXY-MESSAGE (DER, nothing after it),
//     a kerb-message whose length prefix does not match, or one that is not a
//     request: 400. The specification says to drop the connection on a
//     malformed Kerberos message; a status line costs the proxy nothing and
//     tells a person debugging a client what happened;
//   - a missing target-domain: 400 (the specification's ERROR_BAD_FORMAT);
//   - another realm: 403. A Windows client reports 403 as a firewall refusal
//     and any other error as "no logon servers"; either way it tries its next
//     proxy.
//
// Nothing here authenticates the caller: like port 88, it answers anyone, and
// what it answers is what the KDC answers (a KRB-ERROR for an unknown person,
// a ticket only to whoever proves a key).
func (s *Server) KKDCPHandler() http.Handler {
	return http.HandlerFunc(s.serveKKDCP)
}

func (s *Server) serveKKDCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST a KDC-PROXY-MESSAGE", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, kkdcpMaxBody))
	if err != nil {
		if _, tooBig := err.(*http.MaxBytesError); tooBig {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "unreadable body", http.StatusBadRequest)
		}
		return
	}
	inner, realm, err := parseProxyMessage(body)
	if err != nil {
		s.logf("kdc: kkdcp: refused a request: %v", err)
		http.Error(w, "not a KDC-PROXY-MESSAGE", http.StatusBadRequest)
		return
	}
	if realm == "" {
		s.logf("kdc: kkdcp: refused a request with no target-domain")
		http.Error(w, "target-domain is required", http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(realm, s.cfg.Realm) {
		s.logf("kdc: kkdcp: refused a request for realm %q (this one serves %q)", realm, s.cfg.Realm)
		http.Error(w, "this proxy does not serve that realm", http.StatusForbidden)
		return
	}
	out := s.handle(inner)
	if len(out) == 0 {
		// The dispatcher's "nothing sensible can be said": answering noise would
		// make this a reflector, as it would on UDP.
		http.Error(w, "not a Kerberos request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/kerberos")
	w.WriteHeader(http.StatusOK)
	w.Write(marshalProxyMessage(out))
}

// parseProxyMessage reads one KDC-PROXY-MESSAGE and returns the Kerberos
// message without its length prefix, and the target-domain ("" when absent).
// Anything else (trailing bytes, a prefix that disagrees with the message, a
// length with the reserved high bit, a message over the bound) is an error.
func parseProxyMessage(b []byte) (msg []byte, realm string, err error) {
	var pm proxyMessage
	rest, err := asn1.Unmarshal(b, &pm)
	if err != nil {
		return nil, "", err
	}
	if len(rest) != 0 {
		return nil, "", errTrailing
	}
	k := pm.KerbMessage
	if len(k) < 4 {
		return nil, "", errPrefix
	}
	n := binary.BigEndian.Uint32(k)
	if n&0x8000_0000 != 0 || n > maxRequest || int(n) != len(k)-4 {
		return nil, "", errPrefix
	}
	return k[4:], pm.TargetDomain, nil
}

// marshalProxyMessage wraps a reply: its length first, no target-domain
// (not used in a server's message).
//
// It writes the DER by hand, SEQUENCE { [0] EXPLICIT OCTET STRING }, because
// that is all a server's message holds and the encoder's one failure mode
// (a value it cannot represent) cannot arise: a test holds it equal to the
// encoder's output at the lengths where DER changes shape.
func marshalProxyMessage(reply []byte) []byte {
	octets := make([]byte, 0, 4+len(reply))
	octets = binary.BigEndian.AppendUint32(octets, uint32(len(reply)))
	octets = append(octets, reply...)
	str := append(derHeader(0x04, len(octets)), octets...) // OCTET STRING
	ctx := append(derHeader(0xa0, len(str)), str...)       // [0] EXPLICIT
	return append(derHeader(0x30, len(ctx)), ctx...)       // SEQUENCE
}

// derHeader is a tag and a definite length, short form below 128 and the
// minimal long form above (X.690 8.1.3).
func derHeader(tag byte, n int) []byte {
	if n < 0x80 {
		return []byte{tag, byte(n)}
	}
	var l []byte
	for x := n; x > 0; x >>= 8 {
		l = append([]byte{byte(x)}, l...)
	}
	return append([]byte{tag, 0x80 | byte(len(l))}, l...)
}

type kkdcpError string

func (e kkdcpError) Error() string { return string(e) }

const (
	errTrailing kkdcpError = "bytes after the KDC-PROXY-MESSAGE"
	errPrefix   kkdcpError = "kerb-message's length prefix does not match the message"
)
