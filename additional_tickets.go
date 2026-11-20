package kdc

import (
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/types"
)

// additionalTicketsUnreadable reports a request whose additional-tickets field
// gokrb5 v8.4.4 would hand to messages.unmarshalTicketsSequence in a shape
// that function cannot read.
//
// ⛔ That function reads the length header of the value it is given
// (asn1tools.GetNumberBytesInLengthHeader, Ticket.go:134) by indexing its
// second byte, so a one-byte value panics: index out of range [1] with
// length 1 (go-authn/kdc#28). It runs inside (*ASReq).Unmarshal, before any
// authentication. The recover in serve keeps the process alive, but a decoder
// we know will panic on a datagram should not be handed that datagram.
//
// The field does not even have to be [11]. gofork's decoder lets an OPTIONAL
// RawValue take whatever element is next, whatever its tag: the input
// FuzzHandle found has an INTEGER left over inside etype [8], and it is that
// INTEGER (universal tag 2, one byte of content) that arrives as the
// "additional tickets".
//
// RFC 4120 §5.4.1: additional-tickets [11] SEQUENCE OF Ticket OPTIONAL. So
// when gokrb5 would look at the field at all (a non-empty value), this
// demands exactly that: a context-specific [11] holding one complete
// universal SEQUENCE and nothing after it. A SEQUENCE's encoding is at least
// two bytes, which is all the indexing above needs. What is inside the
// SEQUENCE is left to gokrb5, which decodes it with encoding/asn1 and fails
// rather than panics.
//
// The body is decoded with the SAME struct gokrb5 uses (marshalKDCReqBody,
// KDCReq.go:54, unexported there, so mirrored here) through the same
// decoder: a guard that read the body differently could pass a value gokrb5
// then reads as malformed.
func additionalTicketsUnreadable(req []byte) bool {
	for _, tag := range []int{asnAppTag.ASREQ, asnAppTag.TGSREQ} {
		body := kdcReqBody(req, tag)
		if body == nil {
			continue
		}
		var m mirrorKDCReqBody
		if _, err := asn1.Unmarshal(body, &m); err != nil {
			continue // gokrb5 fails on the same bytes the same way, before the tickets
		}
		at := m.AdditionalTickets
		if len(at.Bytes) == 0 {
			continue // gokrb5 does not look at an empty one (KDCReq.go:341)
		}
		if at.Class != asn1.ClassContextSpecific || at.Tag != 11 || !at.IsCompound {
			return true
		}
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(at.Bytes, &seq)
		if err != nil || len(rest) != 0 ||
			seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
			return true
		}
	}
	return false
}

// mirrorKDCReqBody is gokrb5 v8.4.4's marshalKDCReqBody, field for field and
// tag for tag. A gokrb5 upgrade must re-read it: if the original changes,
// this one has to change with it.
type mirrorKDCReqBody struct {
	KDCOptions        asn1.BitString      `asn1:"explicit,tag:0"`
	CName             types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm             string              `asn1:"generalstring,explicit,tag:2"`
	SName             types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From              time.Time           `asn1:"generalized,explicit,optional,tag:4"`
	Till              time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime             time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	Nonce             int                 `asn1:"explicit,tag:7"`
	EType             []int32             `asn1:"explicit,tag:8"`
	Addresses         []types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData       types.EncryptedData `asn1:"explicit,optional,tag:10"`
	AdditionalTickets asn1.RawValue       `asn1:"explicit,optional,tag:11"`
}
