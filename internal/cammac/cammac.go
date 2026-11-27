// Package cammac writes and reads the Container of Authentication-Marking
// Authorization Data a ticket-granting ticket carries (RFC 7751, the container
// MIT krb5 calls CAMMAC; RFC 8129 for the authentication indicator in it).
//
// The container is signed with the krbtgt key, so only this KDC can have made
// one: a client cannot add, drop or change what it says (the client's own
// enc-authorization-data is a different field and never read here). What it
// carries, in elements:
//
//   - an AD-AUTHENTICATION-INDICATOR (97) naming HOW the person logged in, from
//     a closed list ([Methods]); absent for a password logon;
//   - the person's uidNumber when the directory has one (an element of a
//     LOCAL-USE negative ad-type, RFC 4120 5.2.6), so that the TGS can tell a
//     name that was deleted and created again from the person the ticket was
//     issued to (CVE-2021-42287's confusion).
//
// The signature is MIT's (cammac.c, krb5_authdata_verify_cammac): a checksum
// of type 16 (HMAC-SHA1-96-AES256) or 15 under key usage 64 over the DER of
// the EncTicketPart with authorization-data replaced by the container's
// ELEMENTS (not wrapped in AD-IF-RELEVANT). The verifier names the key version
// and omits identifier and enctype.
package cammac

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"unicode/utf8"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	// ADCAMMAC is AD-CAMMAC (RFC 7751).
	ADCAMMAC int32 = 96
	// ADAuthIndicator is AD-AUTHENTICATION-INDICATOR (RFC 8129).
	ADAuthIndicator int32 = 97
	// ADRequestorUID is a LOCAL-USE ad-type (negative, RFC 4120 5.2.6): the
	// requestor's uidNumber as a DER INTEGER.
	ADRequestorUID int32 = -100
	// KeyUsage is KRB5_KEYUSAGE_CAMMAC.
	KeyUsage uint32 = 64
)

// The login methods a bridge can vouch for. The closed list: anything else is
// refused on the way in and on the way out.
const (
	MethodPasskey   = "bridge-passkey"
	MethodFederated = "bridge-federated"
	MethodMachine   = "bridge-machine"
)

// Methods is the closed list of indicator strings.
var Methods = []string{MethodPasskey, MethodFederated, MethodMachine}

// Bounds on what is decoded. The input is a decrypted TGT of ours, but the
// decoder is fuzzed as if it were not.
const (
	MaxContainer   = 4096
	maxElements    = 8
	maxElementData = 512
	maxIndicators  = 4
	maxIndicator   = 64
)

// Errors.
var (
	// ErrMalformed reports a container that does not decode within the bounds.
	ErrMalformed = errors.New("cammac: malformed container")
	// ErrUnsigned reports a container with no kdc-verifier.
	ErrUnsigned = errors.New("cammac: no kdc-verifier")
	// ErrBadMAC reports a verifier that does not match.
	ErrBadMAC = errors.New("cammac: kdc-verifier does not verify")
)

// Claims is what a verified container says.
type Claims struct {
	// Methods are the indicator strings, from [Methods]; none for a password
	// logon.
	Methods []string
	// UID is the requestor's uidNumber; zero when the directory held none.
	UID uint32
}

// Minted says whether a bridge vouched for the logon.
func (c Claims) Minted() bool { return len(c.Methods) > 0 }

// KnownMethod says whether m is on the closed list.
func KnownMethod(m string) bool {
	return slices.Contains(Methods, m)
}

// verifierMAC is Verifier-MAC (RFC 7751) as MIT's kdc-verifier writes it:
// identifier and enctype are left out, and a container that has them does not
// parse here (refused, never skipped).
type verifierMAC struct {
	KVNO int            `asn1:"explicit,tag:1"`
	MAC  types.Checksum `asn1:"explicit,tag:3"`
}

type container struct {
	Elements types.AuthorizationData `asn1:"explicit,tag:0"`
	Verifier verifierMAC             `asn1:"optional,explicit,tag:1"`
}

// elements builds the signed elements for c.
func elements(c Claims) (types.AuthorizationData, error) {
	out := types.AuthorizationData{}
	if len(c.Methods) > maxIndicators {
		return nil, fmt.Errorf("cammac: %d indicators", len(c.Methods))
	}
	if len(c.Methods) > 0 {
		for _, m := range c.Methods {
			if !KnownMethod(m) {
				return nil, fmt.Errorf("cammac: unknown login method %q", m)
			}
		}
		out = append(out, types.AuthorizationDataEntry{ADType: ADAuthIndicator, ADData: encodeIndicators(c.Methods)})
	}
	if c.UID != 0 {
		b, err := asn1.Marshal(int64(c.UID))
		if err != nil {
			return nil, err
		}
		out = append(out, types.AuthorizationDataEntry{ADType: ADRequestorUID, ADData: b})
	}
	return out, nil
}

// signedBytes is the DER the verifier covers: etp with its authorization-data
// replaced by els.
func signedBytes(etp messages.EncTicketPart, els types.AuthorizationData) ([]byte, error) {
	etp.AuthorizationData = els
	b, err := asn1.Marshal(etp)
	if err != nil {
		return nil, err
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart), nil
}

func checksumType(etype int32) (int32, error) {
	switch etype {
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		return chksumtype.HMAC_SHA1_96_AES256, nil
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		return chksumtype.HMAC_SHA1_96_AES128, nil
	}
	return 0, fmt.Errorf("cammac: no checksum for etype %d", etype)
}

// Seal returns the authorization data to put in the ticket: one
// AD-IF-RELEVANT holding the container for c, signed with key (the krbtgt key,
// at version kvno) over etp. etp is the ticket as it will be sent, whatever
// its authorization-data now holds: the field is replaced for the signature.
func Seal(etp messages.EncTicketPart, c Claims, key types.EncryptionKey, kvno int) (types.AuthorizationData, error) {
	els, err := elements(c)
	if err != nil {
		return nil, err
	}
	ct, err := checksumType(key.KeyType)
	if err != nil {
		return nil, err
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	msg, err := signedBytes(etp, els)
	if err != nil {
		return nil, err
	}
	mac, err := et.GetChecksumHash(key.KeyValue, msg, KeyUsage)
	if err != nil {
		return nil, err
	}
	cb, err := asn1.Marshal(container{Elements: els,
		Verifier: verifierMAC{KVNO: kvno, MAC: types.Checksum{CksumType: ct, Checksum: mac}}})
	if err != nil {
		return nil, err
	}
	inner, err := asn1.Marshal(types.AuthorizationData{{ADType: ADCAMMAC, ADData: cb}})
	if err != nil {
		return nil, err
	}
	return types.AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: inner}}, nil
}

// Find looks for the container in a ticket's authorization data, verifies it
// against etp under key, and returns what it says. found is false only when
// there is NO container (a ticket from before the marking); a container that
// is present and does not decode, is unsigned or does not verify is an error,
// never "unmarked".
func Find(etp messages.EncTicketPart, key types.EncryptionKey, kvno int) (c Claims, found bool, err error) {
	var raw []byte
	for _, ad := range etp.AuthorizationData {
		if ad.ADType != adtype.ADIfRelevant {
			continue
		}
		if len(ad.ADData) > MaxContainer {
			return Claims{}, true, ErrMalformed
		}
		var inner types.AuthorizationData
		rest, uerr := asn1.Unmarshal(ad.ADData, &inner)
		if uerr != nil || len(rest) != 0 || len(inner) > maxElements {
			return Claims{}, false, nil // not ours to read: another IF-RELEVANT
		}
		for _, e := range inner {
			if e.ADType == ADCAMMAC {
				if raw != nil {
					return Claims{}, true, ErrMalformed
				}
				raw = e.ADData
				found = true
			}
		}
	}
	if !found {
		return Claims{}, false, nil
	}
	c, err = Verify(raw, etp, key, kvno)
	return c, true, err
}

// Verify decodes one container and checks its verifier. The container must be
// exactly what [Seal] writes (it is re-encoded and compared, so no second
// spelling of the same container is accepted) and name key version kvno, which
// the checksum does not cover.
func Verify(raw []byte, etp messages.EncTicketPart, key types.EncryptionKey, kvno int) (Claims, error) {
	var ct container
	if len(raw) > MaxContainer {
		return Claims{}, ErrMalformed
	}
	rest, err := asn1.Unmarshal(raw, &ct)
	if err != nil || len(rest) != 0 {
		return Claims{}, ErrMalformed
	}
	if len(ct.Elements) > maxElements {
		return Claims{}, ErrMalformed
	}
	v := ct.Verifier
	if len(v.MAC.Checksum) == 0 {
		return Claims{}, ErrUnsigned
	}
	if again, err := asn1.Marshal(ct); err != nil || !bytes.Equal(again, raw) || v.KVNO != kvno {
		return Claims{}, ErrMalformed
	}
	cl, err := decodeElements(ct.Elements)
	if err != nil {
		return Claims{}, err
	}
	want, err := checksumType(key.KeyType)
	if err != nil || v.MAC.CksumType != want {
		return Claims{}, ErrBadMAC
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return Claims{}, ErrBadMAC
	}
	msg, err := signedBytes(etp, ct.Elements)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	if !et.VerifyChecksum(key.KeyValue, msg, v.MAC.Checksum, KeyUsage) {
		return Claims{}, ErrBadMAC
	}
	return cl, nil
}

// Decode reads the elements WITHOUT checking the verifier. It exists for the
// fuzz target and for tools; a ticket is read with [Find].
func Decode(raw []byte) (Claims, error) {
	var ct container
	if len(raw) > MaxContainer {
		return Claims{}, ErrMalformed
	}
	rest, err := asn1.Unmarshal(raw, &ct)
	if err != nil || len(rest) != 0 || len(ct.Elements) > maxElements {
		return Claims{}, ErrMalformed
	}
	return decodeElements(ct.Elements)
}

// encodeIndicators is the DER of SEQUENCE OF UTF8String (RFC 8129): written
// by hand, as the strings are short and the form fixed.
func encodeIndicators(ms []string) []byte {
	var body []byte
	for _, m := range ms {
		body = append(body, 0x0c, byte(len(m)))
		body = append(body, m...)
	}
	if len(body) < 128 {
		return append([]byte{0x30, byte(len(body))}, body...)
	}
	return append([]byte{0x30, 0x81, byte(len(body))}, body...)
}

// decodeIndicators reads that DER strictly: definite short or one-byte long
// lengths, minimal, no trailing bytes, every string valid UTF-8 and on the
// closed list.
func decodeIndicators(b []byte) ([]string, bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return nil, false
	}
	n, off := int(b[1]), 2
	if b[1] == 0x81 {
		if len(b) < 3 || b[2] < 128 {
			return nil, false
		}
		n, off = int(b[2]), 3
	} else if b[1] >= 128 {
		return nil, false
	}
	if len(b)-off != n {
		return nil, false
	}
	b = b[off:]
	var ms []string
	for len(b) > 0 {
		if len(b) < 2 || b[0] != 0x0c || b[1] >= 128 {
			return nil, false
		}
		l := int(b[1])
		if l == 0 || l > maxIndicator || len(b) < 2+l || len(ms) >= maxIndicators {
			return nil, false
		}
		m := string(b[2 : 2+l])
		if !utf8.ValidString(m) || !KnownMethod(m) {
			return nil, false
		}
		ms = append(ms, m)
		b = b[2+l:]
	}
	return ms, len(ms) > 0
}

func decodeElements(els types.AuthorizationData) (Claims, error) {
	var c Claims
	var sawInd, sawUID bool
	for _, e := range els {
		if len(e.ADData) > maxElementData {
			return Claims{}, ErrMalformed
		}
		switch e.ADType {
		case ADAuthIndicator:
			if sawInd {
				return Claims{}, ErrMalformed
			}
			sawInd = true
			ms, ok := decodeIndicators(e.ADData)
			if !ok {
				return Claims{}, ErrMalformed
			}
			c.Methods = ms
		case ADRequestorUID:
			if sawUID {
				return Claims{}, ErrMalformed
			}
			sawUID = true
			var n int64
			rest, err := asn1.Unmarshal(e.ADData, &n)
			if err != nil || len(rest) != 0 || n < 1 || n > math.MaxUint32 {
				return Claims{}, ErrMalformed
			}
			c.UID = uint32(n)
		}
	}
	return c, nil
}
