// Package pac builds, signs and reads the Privilege Attribute Certificate of
// [MS-PAC] that a Kerberos ticket carries in its authorization data.
//
// The KERB_VALIDATION_INFO buffer is NDR (MS-RPCE type serialization v1); it
// is written and read here by hand, because it is one fixed structure and a
// generator would be larger than the structure. Every other buffer is a flat
// little-endian layout.
//
// ⛔ Everything that reads bytes is bounded: a count never drives an
// allocation before it has been checked against the bytes that remain.
package pac

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxSubAuthorities is the NDR limit on a SID's sub-authorities
// ([MS-DTYP] 2.4.2: SubAuthorityCount is at most 15).
const MaxSubAuthorities = 15

// A SID is a security identifier, revision 1.
type SID struct {
	// Authority is the 48-bit identifier authority (5 for NT).
	Authority uint64
	// Sub holds the sub-authorities, the last one being the RID of an account.
	Sub []uint32
}

// ErrBadSID reports a string or a binary form that is not a SID.
var ErrBadSID = errors.New("pac: not a SID")

// ParseSID reads "S-1-5-21-1-2-3". Only revision 1 exists.
func ParseSID(s string) (SID, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" {
		return SID{}, fmt.Errorf("%w: %q", ErrBadSID, s)
	}
	auth, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || auth >= 1<<48 {
		return SID{}, fmt.Errorf("%w: %q: authority", ErrBadSID, s)
	}
	if len(parts)-3 > MaxSubAuthorities {
		return SID{}, fmt.Errorf("%w: %q: more than %d sub-authorities", ErrBadSID, s, MaxSubAuthorities)
	}
	out := SID{Authority: auth}
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return SID{}, fmt.Errorf("%w: %q: sub-authority %q", ErrBadSID, s, p)
		}
		out.Sub = append(out.Sub, uint32(v))
	}
	return out, nil
}

// String is the S-1-... form.
func (s SID) String() string {
	var b strings.Builder
	b.WriteString("S-1-")
	b.WriteString(strconv.FormatUint(s.Authority, 10))
	for _, v := range s.Sub {
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// WithRID is the SID of an account in the domain this SID names.
func (s SID) WithRID(rid uint32) SID {
	sub := make([]uint32, len(s.Sub), len(s.Sub)+1)
	copy(sub, s.Sub)
	return SID{Authority: s.Authority, Sub: append(sub, rid)}
}

// Equal compares two SIDs.
func (s SID) Equal(o SID) bool {
	if s.Authority != o.Authority || len(s.Sub) != len(o.Sub) {
		return false
	}
	for i := range s.Sub {
		if s.Sub[i] != o.Sub[i] {
			return false
		}
	}
	return true
}

// Binary is the wire form: revision, count, 6 big-endian authority bytes, then
// the sub-authorities little-endian ([MS-DTYP] 2.4.2.2). It is what
// REQUESTOR_SID and the SID of UPN_DNS_INFO hold.
func (s SID) Binary() []byte {
	b := make([]byte, 8, 8+4*len(s.Sub))
	b[0] = 1
	b[1] = byte(len(s.Sub))
	for i := 0; i < 6; i++ {
		b[2+i] = byte(s.Authority >> (8 * (5 - i)))
	}
	for _, v := range s.Sub {
		b = append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return b
}

// ParseBinarySID reads the wire form and requires it to fill b exactly.
func ParseBinarySID(b []byte) (SID, error) {
	if len(b) < 8 || b[0] != 1 {
		return SID{}, fmt.Errorf("%w: header", ErrBadSID)
	}
	n := int(b[1])
	if n > MaxSubAuthorities || len(b) != 8+4*n {
		return SID{}, fmt.Errorf("%w: %d sub-authorities in %d bytes", ErrBadSID, n, len(b))
	}
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = auth<<8 | uint64(b[2+i])
	}
	out := SID{Authority: auth}
	for i := 0; i < n; i++ {
		o := 8 + 4*i
		out.Sub = append(out.Sub, uint32(b[o])|uint32(b[o+1])<<8|uint32(b[o+2])<<16|uint32(b[o+3])<<24)
	}
	return out, nil
}
