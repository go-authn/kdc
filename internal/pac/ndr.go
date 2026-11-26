package pac

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Bounds on what a decoder accepts. Encoding refuses the same sizes.
const (
	// MaxLogonInfo is the largest KERB_VALIDATION_INFO buffer read or written.
	MaxLogonInfo = 1 << 20
	// MaxGroupEntries bounds GroupIds, ExtraSids and ResourceGroupIds each.
	MaxGroupEntries = 4096
	// MaxStringUnits bounds one RPC_UNICODE_STRING, in UTF-16 code units.
	MaxStringUnits = 1024
)

// Errors of the NDR layer.
var (
	// ErrNDR reports bytes that are not a KERB_VALIDATION_INFO this package
	// accepts. The wrapped text says where.
	ErrNDR = errors.New("pac: malformed KERB_VALIDATION_INFO")
	// ErrTooBig reports a value over one of the bounds above, on encoding.
	ErrTooBig = errors.New("pac: value over its bound")
)

// A Group is a GROUP_MEMBERSHIP: a RID in the domain and its attributes.
type Group struct {
	RID   uint32
	Attrs uint32
}

// An ExtraSID is a KERB_SID_AND_ATTRIBUTES.
type ExtraSID struct {
	SID   SID
	Attrs uint32
}

// Attribute values of [MS-PAC] 2.2.1.
const (
	// GroupAttrs is SE_GROUP_MANDATORY | ENABLED_BY_DEFAULT | ENABLED.
	GroupAttrs uint32 = 7
)

// LogonInfo is KERB_VALIDATION_INFO ([MS-PAC] 2.5). Times are FILETIMEs.
type LogonInfo struct {
	LogonTime          uint64
	LogoffTime         uint64
	KickOffTime        uint64
	PasswordLastSet    uint64
	PasswordCanChange  uint64
	PasswordMustChange uint64

	EffectiveName      string
	FullName           string
	LogonScript        string
	ProfilePath        string
	HomeDirectory      string
	HomeDirectoryDrive string

	LogonCount       uint16
	BadPasswordCount uint16
	UserID           uint32
	PrimaryGroupID   uint32
	Groups           []Group
	UserFlags        uint32
	UserSessionKey   [16]byte

	LogonServer     string
	LogonDomainName string
	LogonDomainID   SID

	Reserved1            [2]uint32
	UserAccountControl   uint32
	SubAuthStatus        uint32
	LastSuccessfulILogon uint64
	LastFailedILogon     uint64
	FailedILogonCount    uint32
	Reserved3            uint32

	ExtraSIDs []ExtraSID

	// ResourceGroupDomainSID is nil when there are no resource groups.
	ResourceGroupDomainSID *SID
	ResourceGroups         []Group
}

// FileTimeNever is the FILETIME of "never" ([MS-PAC] 2.5).
const FileTimeNever uint64 = 0x7FFFFFFFFFFFFFFF

// type serialization header ([MS-RPCE] 2.2.6.1): version 1, little-endian,
// 8 bytes of common header, a filler of 0xCCCCCCCC.
var commonHeader = [8]byte{0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc}

// firstReferent is the referent id Windows gives the top-level pointer; the
// following ones go up by 4, in the order the pointers are met.
const firstReferent uint32 = 0x00020000

type writer struct {
	b   []byte
	ref uint32
	err error
}

func (w *writer) u16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64) { w.b = binary.LittleEndian.AppendUint64(w.b, v) }
func (w *writer) align(n int) {
	for len(w.b)%n != 0 {
		w.b = append(w.b, 0)
	}
}

// next hands out the following referent id.
func (w *writer) next() uint32 {
	r := w.ref
	w.ref += 4
	return r
}

func (w *writer) fail(format string, args ...any) {
	if w.err == nil {
		w.err = fmt.Errorf("%w: "+format, append([]any{ErrTooBig}, args...)...)
	}
}

// ustr is one RPC_UNICODE_STRING's fixed part; its buffer goes in a deferred
// function so that the buffers follow the whole fixed part, as NDR orders them.
func (w *writer) ustr(s string, deferred *[]func()) {
	u := utf16.Encode([]rune(strings.ToValidUTF8(s, "�")))
	if len(u) > MaxStringUnits {
		w.fail("a string of %d UTF-16 units", len(u))
		return
	}
	w.u16(uint16(2 * len(u)))
	w.u16(uint16(2 * len(u)))
	if len(u) == 0 { // an empty string is a null pointer, as Samba writes it
		w.u32(0)
		return
	}
	w.u32(w.next())
	*deferred = append(*deferred, func() {
		w.u32(uint32(len(u))) // maximum count
		w.u32(0)              // offset
		w.u32(uint32(len(u))) // actual count
		for _, c := range u {
			w.u16(c)
		}
		w.align(4)
	})
}

// sid writes the deferred form of a SID: the conformant sub-authority count,
// then the SID.
func (w *writer) sid(s SID) {
	if len(s.Sub) > MaxSubAuthorities {
		w.fail("a SID of %d sub-authorities", len(s.Sub))
		return
	}
	w.u32(uint32(len(s.Sub)))
	w.b = append(w.b, s.Binary()...)
}

func (w *writer) groups(gs []Group) {
	w.u32(uint32(len(gs)))
	for _, g := range gs {
		w.u32(g.RID)
		w.u32(g.Attrs)
	}
}

// Marshal encodes a KERB_VALIDATION_INFO as the PAC LOGON_INFO buffer holds it:
// the type serialization header, the top-level pointer, the structure, and the
// deferred data of its pointers, padded to a multiple of 8.
func (li *LogonInfo) Marshal() ([]byte, error) {
	if len(li.Groups) > MaxGroupEntries || len(li.ExtraSIDs) > MaxGroupEntries ||
		len(li.ResourceGroups) > MaxGroupEntries {
		return nil, fmt.Errorf("%w: %d groups, %d extra SIDs, %d resource groups",
			ErrTooBig, len(li.Groups), len(li.ExtraSIDs), len(li.ResourceGroups))
	}
	w := &writer{ref: firstReferent}
	w.b = append(w.b, commonHeader[:]...)
	w.u32(0) // object buffer length, patched below
	w.u32(0) // filler
	w.u32(w.next())

	var def []func()
	for _, t := range []uint64{li.LogonTime, li.LogoffTime, li.KickOffTime,
		li.PasswordLastSet, li.PasswordCanChange, li.PasswordMustChange} {
		w.u64(t)
	}
	for _, s := range []string{li.EffectiveName, li.FullName, li.LogonScript,
		li.ProfilePath, li.HomeDirectory, li.HomeDirectoryDrive} {
		w.ustr(s, &def)
	}
	w.u16(li.LogonCount)
	w.u16(li.BadPasswordCount)
	w.u32(li.UserID)
	w.u32(li.PrimaryGroupID)
	w.u32(uint32(len(li.Groups)))
	if len(li.Groups) > 0 {
		w.u32(w.next())
		def = append(def, func() { w.groups(li.Groups) })
	} else {
		w.u32(0)
	}
	w.u32(li.UserFlags)
	w.b = append(w.b, li.UserSessionKey[:]...)
	w.ustr(li.LogonServer, &def)
	w.ustr(li.LogonDomainName, &def)
	w.u32(w.next())
	def = append(def, func() { w.sid(li.LogonDomainID) })
	w.u32(li.Reserved1[0])
	w.u32(li.Reserved1[1])
	w.u32(li.UserAccountControl)
	w.u32(li.SubAuthStatus)
	w.u64(li.LastSuccessfulILogon)
	w.u64(li.LastFailedILogon)
	w.u32(li.FailedILogonCount)
	w.u32(li.Reserved3)
	w.u32(uint32(len(li.ExtraSIDs)))
	if len(li.ExtraSIDs) > 0 {
		w.u32(w.next())
		def = append(def, func() {
			w.u32(uint32(len(li.ExtraSIDs)))
			for _, e := range li.ExtraSIDs {
				w.u32(w.next())
				w.u32(e.Attrs)
			}
			for _, e := range li.ExtraSIDs {
				w.sid(e.SID)
			}
		})
	} else {
		w.u32(0)
	}
	if li.ResourceGroupDomainSID != nil {
		w.u32(w.next())
		def = append(def, func() { w.sid(*li.ResourceGroupDomainSID) })
	} else {
		w.u32(0)
	}
	w.u32(uint32(len(li.ResourceGroups)))
	if len(li.ResourceGroups) > 0 {
		w.u32(w.next())
		def = append(def, func() { w.groups(li.ResourceGroups) })
	} else {
		w.u32(0)
	}
	for _, f := range def {
		f()
	}
	w.align(8)
	if w.err != nil {
		return nil, w.err
	}
	// No size check here: every count and string is bounded above, and the
	// largest encoding they allow is well under MaxLogonInfo (a test pins it).
	binary.LittleEndian.PutUint32(w.b[8:], uint32(len(w.b)-16))
	return w.b, nil
}

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: "+format, append([]any{ErrNDR}, args...)...)
	}
}

// need says whether n more bytes exist, and records the failure otherwise.
func (r *reader) need(n int) bool {
	if n < 0 || n > len(r.b)-r.off {
		r.fail("%d bytes wanted at offset %d of %d", n, r.off, len(r.b))
		return false
	}
	return true
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *reader) u64() uint64 {
	if !r.need(8) {
		return 0
	}
	v := binary.LittleEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v
}

func (r *reader) align(n int) {
	pad := (n - r.off%n) % n
	if r.need(pad) {
		r.off += pad
	}
}

type ustrHead struct {
	length, max uint16
	ref         uint32
}

func (r *reader) ustrHead() ustrHead {
	return ustrHead{length: r.u16(), max: r.u16(), ref: r.u32()}
}

// ustrBody reads the deferred buffer of one RPC_UNICODE_STRING.
func (r *reader) ustrBody(h ustrHead) string {
	if h.length%2 != 0 || h.max%2 != 0 || h.length > h.max || int(h.length)/2 > MaxStringUnits {
		r.fail("a string of length %d, maximum %d", h.length, h.max)
		return ""
	}
	if h.ref == 0 {
		if h.length != 0 {
			r.fail("a null string of length %d", h.length)
		}
		return ""
	}
	max, off, act := r.u32(), r.u32(), r.u32()
	// The three counts are checked against the bounds and the header, and the
	// bytes against what remains, before anything is allocated.
	if max > uint32(MaxStringUnits) || off != 0 || act > max || uint32(h.length)/2 != act {
		r.fail("string counts %d/%d/%d for length %d", max, off, act, h.length)
		return ""
	}
	if !r.need(2 * int(act)) {
		return ""
	}
	u := make([]uint16, act)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(r.b[r.off+2*i:])
	}
	r.off += 2 * int(act)
	r.align(4)
	return string(utf16.Decode(u))
}

func (r *reader) sid() SID {
	n := r.u32()
	// Sized in 64 bits so that a hostile conformance cannot wrap on a 32-bit
	// platform; ParseBinarySID refuses more than 15 sub-authorities and a
	// count that disagrees with the conformance (its length check).
	size := 8 + 4*uint64(n)
	if size > uint64(len(r.b)-r.off) {
		r.fail("a SID of %d sub-authorities past the buffer", n)
		return SID{}
	}
	s, err := ParseBinarySID(r.b[r.off : r.off+int(size)])
	if err != nil {
		r.fail("%v", err)
		return SID{}
	}
	r.off += int(size)
	return s
}

// count checks a count against the bound AND the bytes left for entries of
// size each, before the caller allocates.
func (r *reader) count(n uint32, size int, what string) int {
	if n > MaxGroupEntries || uint64(n)*uint64(size) > uint64(len(r.b)-r.off) {
		r.fail("%s: %d entries", what, n)
		return 0
	}
	return int(n)
}

func (r *reader) groups(declared uint32, what string) []Group {
	max := r.u32()
	if max != declared {
		r.fail("%s: conformance %d against count %d", what, max, declared)
		return nil
	}
	n := r.count(max, 8, what)
	if n == 0 { // a non-null pointer to nothing reads as no groups, as a null one does
		return nil
	}
	out := make([]Group, n)
	for i := range out {
		out[i] = Group{RID: r.u32(), Attrs: r.u32()}
	}
	return out
}

// UnmarshalLogonInfo reads a PAC LOGON_INFO buffer. It accepts what Windows,
// Samba and this package write, rejects anything out of bounds, and never
// allocates more than the buffer's own length allows.
func UnmarshalLogonInfo(b []byte) (*LogonInfo, error) {
	r := &reader{b: b}
	if !r.need(20) {
		return nil, r.err
	}
	if [8]byte(b[:8]) != commonHeader {
		return nil, fmt.Errorf("%w: type serialization header % x", ErrNDR, b[:8])
	}
	r.off = 8
	objLen := r.u32()
	if filler := r.u32(); filler != 0 {
		r.fail("a private header filler of %d", filler)
	}
	if r.err == nil && (int(objLen) != len(b)-16 || objLen%8 != 0) {
		r.fail("an object length of %d in %d bytes", objLen, len(b))
	}
	if top := r.u32(); r.err == nil && top == 0 {
		r.fail("a null top-level pointer")
	}
	li := &LogonInfo{}
	li.LogonTime, li.LogoffTime, li.KickOffTime = r.u64(), r.u64(), r.u64()
	li.PasswordLastSet, li.PasswordCanChange, li.PasswordMustChange = r.u64(), r.u64(), r.u64()
	var heads [6]ustrHead
	for i := range heads {
		heads[i] = r.ustrHead()
	}
	li.LogonCount, li.BadPasswordCount = r.u16(), r.u16()
	li.UserID, li.PrimaryGroupID = r.u32(), r.u32()
	groupCount := r.u32()
	groupRef := r.u32()
	li.UserFlags = r.u32()
	if r.need(16) {
		copy(li.UserSessionKey[:], r.b[r.off:])
		r.off += 16
	}
	serverHead := r.ustrHead()
	domainHead := r.ustrHead()
	domainSIDRef := r.u32()
	li.Reserved1[0], li.Reserved1[1] = r.u32(), r.u32()
	li.UserAccountControl, li.SubAuthStatus = r.u32(), r.u32()
	li.LastSuccessfulILogon, li.LastFailedILogon = r.u64(), r.u64()
	li.FailedILogonCount, li.Reserved3 = r.u32(), r.u32()
	sidCount := r.u32()
	sidsRef := r.u32()
	resSIDRef := r.u32()
	resCount := r.u32()
	resRef := r.u32()

	strs := make([]string, 6)
	for i := range strs {
		strs[i] = r.ustrBody(heads[i])
	}
	li.EffectiveName, li.FullName, li.LogonScript = strs[0], strs[1], strs[2]
	li.ProfilePath, li.HomeDirectory, li.HomeDirectoryDrive = strs[3], strs[4], strs[5]

	if groupRef != 0 {
		li.Groups = r.groups(groupCount, "GroupIds")
	} else if groupCount != 0 {
		r.fail("GroupIds: %d entries behind a null pointer", groupCount)
	}
	li.LogonServer = r.ustrBody(serverHead)
	li.LogonDomainName = r.ustrBody(domainHead)
	if domainSIDRef == 0 {
		r.fail("a null LogonDomainId")
	} else {
		li.LogonDomainID = r.sid()
	}

	switch {
	case sidsRef != 0:
		max := r.u32()
		if r.err == nil && max != sidCount {
			r.fail("ExtraSids: conformance %d against count %d", max, sidCount)
		}
		n := r.count(max, 8, "ExtraSids")
		type head struct{ ref, attrs uint32 }
		hs := make([]head, n)
		for i := range hs {
			hs[i] = head{ref: r.u32(), attrs: r.u32()}
		}
		for _, h := range hs {
			if h.ref == 0 {
				r.fail("a null ExtraSids SID")
				break
			}
			li.ExtraSIDs = append(li.ExtraSIDs, ExtraSID{SID: r.sid(), Attrs: h.attrs})
		}
	case sidCount != 0:
		r.fail("ExtraSids: %d entries behind a null pointer", sidCount)
	}
	if resSIDRef != 0 {
		s := r.sid()
		li.ResourceGroupDomainSID = &s
	}
	if resRef != 0 {
		li.ResourceGroups = r.groups(resCount, "ResourceGroupIds")
	} else if resCount != 0 {
		r.fail("ResourceGroupIds: %d entries behind a null pointer", resCount)
	}
	if r.err != nil {
		return nil, r.err
	}
	return li, nil
}
