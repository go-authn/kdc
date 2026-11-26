package pac

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Buffer types of [MS-PAC] 2.4.
const (
	TypeLogonInfo       uint32 = 1
	TypeServerChecksum  uint32 = 6
	TypeKDCChecksum     uint32 = 7
	TypeClientInfo      uint32 = 10
	TypeUPNDNSInfo      uint32 = 12
	TypeTicketChecksum  uint32 = 16
	TypeAttributesInfo  uint32 = 17
	TypeRequestorSID    uint32 = 18
	TypeFullChecksum    uint32 = 19
	checksumAES256      uint32 = 16 // HMAC-SHA1-96-AES256, RFC 3962 / RFC 4757 numbering
	checksumLen                = 12
	keyUsageAppDataCksm        = 17
	alignment                  = 8
)

// Bounds of the container.
const (
	// MaxBuffers bounds the number of PAC_INFO_BUFFERs read.
	MaxBuffers = 32
	// MaxPAC bounds the whole PAC, at the size of LOGON_INFO plus slack.
	MaxPAC = MaxLogonInfo + 64<<10
)

// Errors of the container.
var (
	// ErrPAC reports a container that is not a well-formed PAC.
	ErrPAC = errors.New("pac: malformed PAC")
	// ErrSignature reports a checksum that does not verify, or that is of a
	// type this package refuses.
	ErrSignature = errors.New("pac: signature refused")
)

// Input is everything Build puts into a PAC.
type Input struct {
	Logon *LogonInfo

	// ClientName is the CLIENT_INFO name: the principal without its realm.
	ClientName string
	// AuthTime is the ticket's authtime. It is truncated to the second:
	// MIT compares CLIENT_INFO's authtime with the ticket's EXACTLY.
	AuthTime time.Time

	// UPN, DNSDomain and SamName fill UPN_DNS_INFO; UserSID is its SID.
	UPN, DNSDomain, SamName string
	UserSID                 SID

	// RequestorSID fills PAC_REQUESTOR (CVE-2021-42287).
	RequestorSID SID

	// ServiceTicket adds the ticket signature (16) and the full signature (19)
	// (CVE-2022-37967). A TGT carries neither.
	ServiceTicket bool
	// TicketBytes is the EncTicketPart as encoded with the PAC replaced by a
	// single zero byte (MIT's recoding); required when ServiceTicket is set.
	TicketBytes []byte
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func pad8(b []byte) []byte {
	for len(b)%alignment != 0 {
		b = append(b, 0)
	}
	return b
}

func clientInfo(name string, authtime time.Time) []byte {
	n := utf16le(name)
	b := binary.LittleEndian.AppendUint64(nil, unixToFileTime(authtime.Unix()))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(n)))
	return append(b, n...)
}

// unixToFileTime converts seconds since 1970 to a FILETIME.
func unixToFileTime(sec int64) uint64 { return uint64(sec+11644473600) * 10000000 }

// FileTime converts a time to a FILETIME, with 100 ns resolution.
func FileTime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600)*10000000 + uint64(t.Nanosecond()/100)
}

func upnDNSInfo(upn, dns, sam string, sid SID) []byte {
	u, d, s, sb := utf16le(upn), utf16le(dns), utf16le(sam), sid.Binary()
	const head = 24
	off := head
	next := func(n int) int {
		o := off
		off = (off + n + alignment - 1) &^ (alignment - 1)
		return o
	}
	uo, do, so, sido := next(len(u)), next(len(d)), next(len(s)), next(len(sb))
	b := make([]byte, off)
	binary.LittleEndian.PutUint16(b[0:], uint16(len(u)))
	binary.LittleEndian.PutUint16(b[2:], uint16(uo))
	binary.LittleEndian.PutUint16(b[4:], uint16(len(d)))
	binary.LittleEndian.PutUint16(b[6:], uint16(do))
	binary.LittleEndian.PutUint32(b[8:], 2) // S_FLAG: SamName and Sid are present
	binary.LittleEndian.PutUint16(b[12:], uint16(len(s)))
	binary.LittleEndian.PutUint16(b[14:], uint16(so))
	binary.LittleEndian.PutUint16(b[16:], uint16(len(sb)))
	binary.LittleEndian.PutUint16(b[18:], uint16(sido))
	copy(b[uo:], u)
	copy(b[do:], d)
	copy(b[so:], s)
	copy(b[sido:], sb)
	return b
}

type buf struct {
	typ  uint32
	data []byte
}

// checksum is key's mandatory checksum over data, with the PAC key usage.
// The key must have passed validKey: it then cannot fail, and a nil result
// (which no signature equals) is what an impossible failure would read as.
func checksum(key types.EncryptionKey, data []byte) []byte {
	h, _ := aes256.GetChecksumHash(key.KeyValue, data, keyUsageAppDataCksm)
	return h
}

var aes256 = func() etype.EType {
	et, err := crypto.GetEtype(18)
	if err != nil {
		panic(err) // aes256-cts-hmac-sha1-96 is compiled into gokrb5
	}
	return et
}()

// validKey says whether key is an AES-256 key, the only type signed with.
func validKey(key types.EncryptionKey) bool {
	return key.KeyType == 18 && len(key.KeyValue) == 32
}

func sigBuf() []byte {
	b := make([]byte, 4+checksumLen)
	binary.LittleEndian.PutUint32(b, checksumAES256)
	return b
}

// Build assembles and signs a PAC. serverKey seals the server signature and
// kdcKey (the krbtgt key) the KDC signatures, in the order MIT writes them:
// ticket (16), full (19), server (6), KDC (7).
func Build(in *Input, serverKey, kdcKey types.EncryptionKey) ([]byte, error) {
	if !validKey(serverKey) || !validKey(kdcKey) {
		return nil, fmt.Errorf("%w: a key that is not AES-256", ErrSignature)
	}
	if in.Logon == nil {
		return nil, fmt.Errorf("%w: no LOGON_INFO", ErrPAC)
	}
	li, err := in.Logon.Marshal()
	if err != nil {
		return nil, err
	}
	var attr [8]byte
	binary.LittleEndian.PutUint32(attr[0:], 2)
	binary.LittleEndian.PutUint32(attr[4:], 1) // PAC_WAS_REQUESTED: the AS-REQ asked for it
	bufs := []buf{
		{TypeLogonInfo, li},
		{TypeClientInfo, clientInfo(in.ClientName, in.AuthTime.Truncate(time.Second))},
		{TypeUPNDNSInfo, upnDNSInfo(in.UPN, in.DNSDomain, in.SamName, in.UserSID)},
		{TypeAttributesInfo, attr[:]},
		{TypeRequestorSID, in.RequestorSID.Binary()},
	}
	if in.ServiceTicket {
		bufs = append(bufs, buf{TypeTicketChecksum, sigBuf()}, buf{TypeFullChecksum, sigBuf()})
	}
	bufs = append(bufs, buf{TypeServerChecksum, sigBuf()}, buf{TypeKDCChecksum, sigBuf()})

	p := layout(bufs)
	at := func(t uint32) []byte { b, _ := p.Buffer(t); return b }
	// Each signature covers the PAC as it stands when it is made: 6, 7 and
	// 19 are zero until their turn.
	steps := []struct {
		typ  uint32
		key  types.EncryptionKey
		data func() []byte
		skip bool
	}{
		{TypeTicketChecksum, kdcKey, func() []byte { return in.TicketBytes }, !in.ServiceTicket},
		{TypeFullChecksum, kdcKey, func() []byte { return p.Raw }, !in.ServiceTicket},
		{TypeServerChecksum, serverKey, func() []byte { return p.Raw }, false},
		{TypeKDCChecksum, kdcKey, func() []byte { return at(TypeServerChecksum)[4:] }, false},
	}
	for _, s := range steps {
		if !s.skip {
			copy(at(s.typ)[4:], checksum(s.key, s.data()))
		}
	}
	return p.Raw, nil
}

// layout writes the PACTYPE header and the buffers, each at an 8-aligned offset.
func layout(bufs []buf) *PAC {
	head := 8 + 16*len(bufs)
	out := make([]byte, 0, head+1024)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(bufs)))
	out = binary.LittleEndian.AppendUint32(out, 0)
	off := (head + alignment - 1) &^ (alignment - 1)
	body := []byte{}
	p := &PAC{}
	for _, b := range bufs {
		start := off + len(body)
		out = binary.LittleEndian.AppendUint32(out, b.typ)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(b.data)))
		out = binary.LittleEndian.AppendUint64(out, uint64(start))
		body = pad8(append(body, b.data...))
		p.list = append(p.list, entry{b.typ, start, start + len(b.data)})
	}
	out = pad8(out)
	p.Raw = append(out, body...)
	return p
}

// A PAC is a parsed container. Its buffers alias Raw.
type PAC struct {
	Raw  []byte
	list []entry
}

type entry struct {
	typ        uint32
	start, end int
}

// Parse reads the PACTYPE header with every offset and size checked against
// the length of b before any of it is used.
func Parse(b []byte) (*PAC, error) {
	if len(b) < 8 || len(b) > MaxPAC {
		return nil, fmt.Errorf("%w: %d bytes", ErrPAC, len(b))
	}
	n := binary.LittleEndian.Uint32(b)
	if v := binary.LittleEndian.Uint32(b[4:]); v != 0 || n == 0 || n > MaxBuffers {
		return nil, fmt.Errorf("%w: version %d, %d buffers", ErrPAC, v, n)
	}
	head := 8 + 16*int(n)
	if head > len(b) {
		return nil, fmt.Errorf("%w: header of %d bytes in %d", ErrPAC, head, len(b))
	}
	p := &PAC{Raw: b}
	seen := map[uint32]bool{}
	for i := 0; i < int(n); i++ {
		e := b[8+16*i:]
		t := binary.LittleEndian.Uint32(e)
		size := uint64(binary.LittleEndian.Uint32(e[4:]))
		off := binary.LittleEndian.Uint64(e[8:])
		if off%alignment != 0 || off < uint64(head) || off > uint64(len(b)) || size > uint64(len(b))-off {
			return nil, fmt.Errorf("%w: buffer %d at %d size %d", ErrPAC, t, off, size)
		}
		if seen[t] {
			return nil, fmt.Errorf("%w: buffer %d twice", ErrPAC, t)
		}
		seen[t] = true
		p.list = append(p.list, entry{t, int(off), int(off) + int(size)})
	}
	return p, nil
}

// Buffer returns the bytes of the buffer of type t, aliasing Raw.
func (p *PAC) Buffer(t uint32) ([]byte, bool) {
	for _, e := range p.list {
		if e.typ == t {
			return p.Raw[e.start:e.end:e.end], true
		}
	}
	return nil, false
}

// Verify checks the signatures the way MIT's krb5_kdc_verify_ticket does.
// A service ticket (wantTicketSig) must carry 16 and 19, and ticketBytes is the
// EncTicketPart recoded with the PAC replaced by one zero byte. Only the
// checksum type 16 is accepted: HMAC-MD5 (-138) and the rest are refused.
func (p *PAC) Verify(serverKey, kdcKey types.EncryptionKey, wantTicketSig bool, ticketBytes []byte) error {
	if !validKey(serverKey) || !validKey(kdcKey) {
		return fmt.Errorf("%w: a key that is not AES-256", ErrSignature)
	}
	// Every signature wanted is present, of the one type accepted, at its size.
	want := []uint32{TypeServerChecksum, TypeKDCChecksum}
	if wantTicketSig {
		want = append(want, TypeTicketChecksum, TypeFullChecksum)
	}
	sigs := map[uint32][]byte{}
	for _, t := range want {
		b, _ := p.Buffer(t) // absent: nil, refused by its length
		if len(b) != 4+checksumLen || binary.LittleEndian.Uint32(b) != checksumAES256 {
			return fmt.Errorf("%w: buffer %d absent or not an AES256 checksum", ErrSignature, t)
		}
		sigs[t] = b[4:]
	}
	check := func(key types.EncryptionKey, data, got []byte) error {
		if !hmacEqual(checksum(key, data), got) {
			return fmt.Errorf("%w: checksum mismatch", ErrSignature)
		}
		return nil
	}
	srv, kdc := sigs[TypeServerChecksum], sigs[TypeKDCChecksum]
	if wantTicketSig {
		if err := check(kdcKey, ticketBytes, sigs[TypeTicketChecksum]); err != nil {
			return fmt.Errorf("ticket: %w", err)
		}
	}
	cp := append([]byte(nil), p.Raw...)
	zero := func(t uint32) {
		for _, e := range p.list {
			if e.typ == t {
				clear(cp[e.start+4 : e.end])
			}
		}
	}
	zero(TypeServerChecksum)
	zero(TypeKDCChecksum)
	if err := check(serverKey, cp, srv); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	if wantTicketSig {
		zero(TypeFullChecksum)
		if err := check(kdcKey, cp, sigs[TypeFullChecksum]); err != nil {
			return fmt.Errorf("full: %w", err)
		}
	}
	return check(kdcKey, srv, kdc)
}

func hmacEqual(a, b []byte) bool { return len(a) == len(b) && bytes.Equal(a, b) }

// ClientInfo returns the CLIENT_INFO buffer's authtime (seconds since 1970)
// and name.
func (p *PAC) ClientInfo() (authtime int64, name string, err error) {
	b, ok := p.Buffer(TypeClientInfo)
	if !ok || len(b) < 10 {
		return 0, "", fmt.Errorf("%w: CLIENT_INFO", ErrPAC)
	}
	ft := binary.LittleEndian.Uint64(b)
	n := int(binary.LittleEndian.Uint16(b[8:]))
	if n%2 != 0 || 10+n > len(b) {
		return 0, "", fmt.Errorf("%w: CLIENT_INFO name of %d bytes", ErrPAC, n)
	}
	u := make([]uint16, n/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[10+2*i:])
	}
	return int64(ft/10000000) - 11644473600, string(utf16.Decode(u)), nil
}
