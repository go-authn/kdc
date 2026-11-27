package cammac

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func key(t testing.TB) types.EncryptionKey {
	t.Helper()
	et, err := crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatal(err)
	}
	k, err := types.GenerateEncryptionKey(et)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func etpOf(t testing.TB) messages.EncTicketPart {
	t.Helper()
	fl := types.NewKrbFlags()
	at := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	return messages.EncTicketPart{
		Flags: fl, Key: key(t), CRealm: "EXAMPLE.ORG",
		CName:    types.PrincipalName{NameType: 1, NameString: []string{"alice"}},
		AuthTime: at, StartTime: at, EndTime: at.Add(time.Hour),
	}
}

// wire marshals etp with ad as its authorization data and reads it back, as a
// TGS does after decrypting a ticket.
func wire(t testing.TB, etp messages.EncTicketPart, ad types.AuthorizationData) messages.EncTicketPart {
	t.Helper()
	etp.AuthorizationData = ad
	b, err := asn1.Marshal(etp)
	if err != nil {
		t.Fatal(err)
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart)
	var out messages.EncTicketPart
	if _, err := asn1.UnmarshalWithParams(b, &out, "application,explicit,tag:3"); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSealThenFind(t *testing.T) {
	k := key(t)
	for _, c := range []Claims{
		{},
		{UID: 1001},
		{Methods: []string{MethodPasskey}, UID: 4000000000},
		{Methods: []string{MethodFederated, MethodMachine}},
	} {
		etp := etpOf(t)
		ad, err := Seal(etp, c, k, 3)
		if err != nil {
			t.Fatal(err)
		}
		got, found, err := Find(wire(t, etp, ad), k, 3)
		if err != nil || !found {
			t.Fatalf("%+v: found=%v err=%v", c, found, err)
		}
		if fmt.Sprint(got) != fmt.Sprint(c) {
			t.Fatalf("got %+v want %+v", got, c)
		}
	}
}

func TestNoContainerIsUnmarked(t *testing.T) {
	_, found, err := Find(wire(t, etpOf(t), nil), key(t), 1)
	if found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestRefusals(t *testing.T) {
	k := key(t)
	etp := etpOf(t)
	c := Claims{Methods: []string{MethodPasskey}, UID: 1001}
	ad, err := Seal(etp, c, k, 1)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong key", func(t *testing.T) {
		if _, _, err := Find(wire(t, etp, ad), key(t), 1); !errors.Is(err, ErrBadMAC) {
			t.Fatal(err)
		}
	})
	t.Run("another ticket", func(t *testing.T) {
		other := etp
		other.CName.NameString = []string{"mallory"}
		if _, _, err := Find(wire(t, other, ad), k, 1); !errors.Is(err, ErrBadMAC) {
			t.Fatal(err)
		}
	})
	t.Run("session key changed", func(t *testing.T) {
		other := etp
		other.Key = key(t)
		if _, _, err := Find(wire(t, other, ad), k, 1); !errors.Is(err, ErrBadMAC) {
			t.Fatal(err)
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		els, _ := elements(c)
		cb, err := asn1.Marshal(struct {
			Elements types.AuthorizationData `asn1:"explicit,tag:0"`
		}{els})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(cb, etp, k, 1); !errors.Is(err, ErrUnsigned) {
			t.Fatal(err)
		}
	})
	t.Run("forged verifier", func(t *testing.T) {
		els, _ := elements(c)
		cb, err := asn1.Marshal(container{Elements: els, Verifier: verifierMAC{KVNO: 1,
			MAC: types.Checksum{CksumType: 16, Checksum: bytes.Repeat([]byte{7}, 12)}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(cb, etp, k, 1); !errors.Is(err, ErrBadMAC) {
			t.Fatal(err)
		}
	})
	t.Run("elements swapped under a good verifier", func(t *testing.T) {
		good, _ := Seal(etp, Claims{UID: 1001}, k, 1)
		forged, _ := Seal(etp, Claims{Methods: []string{MethodMachine}, UID: 1001}, key(t), 1)
		// the forger's elements, the real verifier
		raw := func(ad types.AuthorizationData) container {
			var in types.AuthorizationData
			asn1.Unmarshal(ad[0].ADData, &in)
			var ct container
			asn1.Unmarshal(in[0].ADData, &ct)
			return ct
		}
		ct := container{Elements: raw(forged).Elements, Verifier: raw(good).Verifier}
		cb, _ := asn1.Marshal(ct)
		if _, err := Verify(cb, etp, k, 1); !errors.Is(err, ErrBadMAC) {
			t.Fatal(err)
		}
	})
	t.Run("every flipped byte is refused", func(t *testing.T) {
		var in types.AuthorizationData
		asn1.Unmarshal(ad[0].ADData, &in)
		raw := in[0].ADData
		for i := range raw {
			m := bytes.Clone(raw)
			m[i] ^= 0x01
			if got, err := Verify(m, etp, k, 1); err == nil {
				t.Fatalf("byte %d flipped and accepted: %+v", i, got)
			}
		}
	})
	t.Run("trailing bytes and oversize", func(t *testing.T) {
		var in types.AuthorizationData
		asn1.Unmarshal(ad[0].ADData, &in)
		if _, err := Verify(append(bytes.Clone(in[0].ADData), 0), etp, k, 1); err == nil {
			t.Fatal("trailing byte accepted")
		}
		if _, err := Verify(make([]byte, MaxContainer+1), etp, k, 1); !errors.Is(err, ErrMalformed) {
			t.Fatal(err)
		}
	})
	t.Run("two containers", func(t *testing.T) {
		var in types.AuthorizationData
		asn1.Unmarshal(ad[0].ADData, &in)
		twice, _ := asn1.Marshal(types.AuthorizationData{in[0], in[0]})
		two := types.AuthorizationData{{ADType: 1, ADData: twice}}
		two[0].ADType = ad[0].ADType
		if _, _, err := Find(wire(t, etp, two), k, 1); !errors.Is(err, ErrMalformed) {
			t.Fatal(err)
		}
	})
}

func TestSealRefusesWhatItCannotSay(t *testing.T) {
	k := key(t)
	if _, err := Seal(etpOf(t), Claims{Methods: []string{"password"}}, k, 1); err == nil {
		t.Fatal("an unknown method was sealed")
	}
	five := []string{MethodPasskey, MethodPasskey, MethodPasskey, MethodPasskey, MethodPasskey}
	if _, err := Seal(etpOf(t), Claims{Methods: five}, k, 1); err == nil {
		t.Fatal("five indicators sealed")
	}
	k.KeyType = 23
	if _, err := Seal(etpOf(t), Claims{}, k, 1); err == nil {
		t.Fatal("rc4 sealed")
	}
}

func TestDecodeIndicators(t *testing.T) {
	for _, bad := range [][]byte{
		nil, {0x30}, {0x30, 0x00}, {0x30, 0x81, 0x01, 0x0c}, {0x31, 0x00},
		{0x30, 0x02, 0x0c, 0x00},
		{0x30, 0x03, 0x0c, 0x01, 0xff},
		{0x30, 0x05, 0x0c, 0x03, 'a', 'b', 'c'},
	} {
		if ms, ok := decodeIndicators(bad); ok {
			t.Fatalf("%x accepted: %v", bad, ms)
		}
	}
	if ms, ok := decodeIndicators(encodeIndicators(Methods)); !ok || fmt.Sprint(ms) != fmt.Sprint(Methods) {
		t.Fatalf("closed list does not round trip: %v %v", ms, ok)
	}
}

func FuzzCAMMACDecode(f *testing.F) {
	k := key(f)
	etp := etpOf(f)
	for _, c := range []Claims{{}, {UID: 7}, {Methods: []string{MethodPasskey}, UID: 1001}} {
		ad, err := Seal(etp, c, k, 1)
		if err != nil {
			f.Fatal(err)
		}
		var in types.AuthorizationData
		asn1.Unmarshal(ad[0].ADData, &in)
		f.Add(in[0].ADData)
	}
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := Decode(raw)
		if err == nil {
			for _, m := range c.Methods {
				if !KnownMethod(m) {
					t.Fatalf("unknown method %q decoded", m)
				}
			}
			if len(c.Methods) > maxIndicators {
				t.Fatal("too many methods")
			}
		}
		// Verify must never accept what was not sealed with this key.
		if _, err := Verify(raw, etp, k, 1); err == nil {
			// Only the seeds can verify; they are 3 specific strings.
			ok := false
			for _, cc := range []Claims{{}, {UID: 7}, {Methods: []string{MethodPasskey}, UID: 1001}} {
				ad, _ := Seal(etp, cc, k, 1)
				var in types.AuthorizationData
				asn1.Unmarshal(ad[0].ADData, &in)
				if bytes.Equal(in[0].ADData, raw) {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("accepted a container nobody sealed: %x", raw)
			}
		}
	})
}

// signedWith seals arbitrary elements, as a KDC with a bug (or an attacker with
// the krbtgt key) could: the MAC is right, so only the decoder's own bounds
// can refuse them.
func signedWith(t testing.TB, etp messages.EncTicketPart, els types.AuthorizationData, k types.EncryptionKey, kvno int) []byte {
	t.Helper()
	ct, err := checksumType(k.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	et, err := crypto.GetEtype(k.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := signedBytes(etp, els)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := et.GetChecksumHash(k.KeyValue, msg, KeyUsage)
	if err != nil {
		t.Fatal(err)
	}
	b, err := asn1.Marshal(container{Elements: els, Verifier: verifierMAC{KVNO: kvno, MAC: types.Checksum{CksumType: ct, Checksum: mac}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ind(b ...byte) types.AuthorizationDataEntry {
	return types.AuthorizationDataEntry{ADType: ADAuthIndicator, ADData: b}
}

func uidEl(b ...byte) types.AuthorizationDataEntry {
	return types.AuthorizationDataEntry{ADType: ADRequestorUID, ADData: b}
}

// str is an indicator element holding the strings, each a UTF8String.
func str(ss ...string) types.AuthorizationDataEntry {
	return ind(encodeIndicators(ss)...)
}

func TestEverySignedButMalformedContainerIsRefused(t *testing.T) {
	k := key(t)
	etp := etpOf(t)
	pk := MethodPasskey
	long := make([]byte, 600)
	many := make(types.AuthorizationData, 9)
	for i := range many {
		many[i] = types.AuthorizationDataEntry{ADType: int32(1000 + i)}
	}
	cases := map[string]types.AuthorizationData{
		"nine elements":                    many,
		"an element over 512 bytes":        {{ADType: 1000, ADData: long}},
		"two indicator elements":           {str(pk), str(pk)},
		"two uid elements":                 {uidEl(0x02, 0x02, 0x03, 0xe9), uidEl(0x02, 0x02, 0x03, 0xe9)},
		"uid zero":                         {uidEl(0x02, 0x01, 0x00)},
		"uid negative":                     {uidEl(0x02, 0x01, 0xff)},
		"uid over 2^32-1":                  {uidEl(0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00)},
		"uid with trailing bytes":          {uidEl(0x02, 0x01, 0x05, 0x00)},
		"uid not an integer":               {uidEl(0x04, 0x01, 0x05)},
		"indicators: empty":                {ind()},
		"indicators: not a sequence":       {ind(0x31, 0x00)},
		"indicators: no strings":           {ind(0x30, 0x00)},
		"indicators: long form, too short": {ind(0x30, 0x81)},
		"indicators: long form under 128":  {ind(append([]byte{0x30, 0x81, 0x10}, append([]byte{0x0c, 0x0e}, make([]byte, 14)...)...)...)},
		"indicators: two-byte length":      {ind(0x30, 0x82, 0x00, 0x00)},
		"indicators: indefinite length":    {ind(0x30, 0x80, 0x00, 0x00)},
		"indicators: length too long":      {ind(0x30, 0x05, 0x0c, 0x01, 'a')},
		"indicators: length too short":     {ind(0x30, 0x01, 0x0c, 0x01, 'a')},
		"indicators: wrong string tag":     {ind(0x30, 0x03, 0x04, 0x01, 'a')},
		"indicators: truncated string":     {ind(0x30, 0x01, 0x0c)},
		"indicators: long string length":   {ind(0x30, 0x03, 0x0c, 0x81, 0x01)},
		"indicators: empty string":         {ind(0x30, 0x02, 0x0c, 0x00)},
		"indicators: unknown method":       {ind(0x30, 0x03, 0x0c, 0x01, 'a')},
		"indicators: invalid UTF-8":        {ind(0x30, 0x03, 0x0c, 0x01, 0xff)},
		"indicators: string runs past end": {ind(0x30, 0x02, 0x0c, 0x05)},
	}
	// A string of 65 bytes (over maxIndicator) and five strings (over maxIndicators).
	s65 := append([]byte{0x30, 0x43, 0x0c, 0x41}, bytes.Repeat([]byte{'a'}, 65)...)
	cases["indicators: string over 64 bytes"] = types.AuthorizationData{ind(s65...)}
	five := []byte{0x30, 5 * (2 + byte(len(pk)))}
	for i := 0; i < 5; i++ {
		five = append(five, 0x0c, byte(len(pk)))
		five = append(five, pk...)
	}
	cases["indicators: five strings"] = types.AuthorizationData{ind(five...)}
	for name, els := range cases {
		raw := signedWith(t, etp, els, k, 3)
		if _, err := Verify(raw, etp, k, 3); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Verify %v, want ErrMalformed", name, err)
		}
		if _, err := Decode(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Decode %v, want ErrMalformed", name, err)
		}
		if _, found, err := Find(wire(t, etp, types.AuthorizationData{wrapIF(t, raw)}), k, 3); !found || err == nil {
			t.Errorf("%s: Find found=%v err=%v", name, found, err)
		}
	}
	// The control: the same machinery accepts a good one.
	good := signedWith(t, etp, types.AuthorizationData{str(pk), uidEl(0x02, 0x02, 0x03, 0xe9)}, k, 3)
	if c, err := Verify(good, etp, k, 3); err != nil || c.UID != 1001 || len(c.Methods) != 1 {
		t.Fatalf("control: %+v %v", c, err)
	}
	// Bounds on the container itself.
	for name, raw := range map[string][]byte{
		"over 4096 bytes":      append(bytes.Clone(good), make([]byte, MaxContainer)...),
		"trailing bytes":       append(bytes.Clone(good), 0),
		"nine elements, bytes": signedWith(t, etp, many, k, 3),
	} {
		if _, err := Verify(raw, etp, k, 3); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Verify %v", name, err)
		}
		if _, err := Decode(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Decode %v", name, err)
		}
	}
}

func wrapIF(t testing.TB, raw []byte) types.AuthorizationDataEntry {
	t.Helper()
	in, err := asn1.Marshal(types.AuthorizationData{{ADType: ADCAMMAC, ADData: raw}})
	if err != nil {
		t.Fatal(err)
	}
	return types.AuthorizationDataEntry{ADType: 1, ADData: in}
}

// A container wrapped in AD-IF-RELEVANT that is too big, and one that is not
// ours at all.
func TestFindBoundsWhatItWillRead(t *testing.T) {
	k := key(t)
	etp := etpOf(t)
	big := types.AuthorizationDataEntry{ADType: 1, ADData: make([]byte, MaxContainer+1)}
	if _, found, err := Find(wire(t, etp, types.AuthorizationData{big}), k, 3); !found || !errors.Is(err, ErrMalformed) {
		t.Errorf("oversize IF-RELEVANT: found=%v err=%v", found, err)
	}
	// Not ours: garbage, trailing bytes, more than 8 elements.
	many := make(types.AuthorizationData, 9)
	for i := range many {
		many[i] = types.AuthorizationDataEntry{ADType: int32(1000 + i)}
	}
	nine, err := asn1.Marshal(many)
	if err != nil {
		t.Fatal(err)
	}
	one, err := asn1.Marshal(types.AuthorizationData{{ADType: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string][]byte{"garbage": {0xff, 0x00}, "trailing": append(one, 0), "nine": nine} {
		ad := types.AuthorizationData{{ADType: 1, ADData: d}}
		if _, found, err := Find(wire(t, etp, ad), k, 3); found || err != nil {
			t.Errorf("%s: found=%v err=%v", name, found, err)
		}
	}
}

// Short inputs to the strict DER reader: each is refused, none is read past its end.
func TestDecodeIndicatorsRefusesTruncations(t *testing.T) {
	pk := []byte{0x0c, byte(len(MethodPasskey))}
	pk = append(pk, MethodPasskey...)
	for name, b := range map[string][]byte{
		"nil":                      nil,
		"one byte":                 {0x30},
		"tag only, no strings":     {0x30, 0x00},
		"long form, no length":     {0x30, 0x81},
		"long form, small length":  {0x30, 0x81, 0x05},
		"two-byte length":          {0x30, 0x82, 0x00, 0x10},
		"indefinite":               {0x30, 0x80},
		"length over the content":  append([]byte{0x30, byte(len(pk) + 1)}, pk...),
		"length under the content": append([]byte{0x30, byte(len(pk) - 1)}, pk...),
		"string tag alone":         {0x30, 0x01, 0x0c},
		"string with long length":  {0x30, 0x03, 0x0c, 0x81, 0x0e},
		"wrong string tag":         append([]byte{0x30, byte(len(pk))}, append([]byte{0x04}, pk[1:]...)...),
	} {
		if ms, ok := decodeIndicators(b); ok || ms != nil {
			t.Errorf("%s: %v %v", name, ms, ok)
		}
	}
	if ms, ok := decodeIndicators(append([]byte{0x30, byte(len(pk))}, pk...)); !ok || len(ms) != 1 {
		t.Errorf("control: %v %v", ms, ok)
	}
}

// A container that parses and verifies but is bigger than the bound.
func TestAWellFormedContainerOverTheBoundIsRefused(t *testing.T) {
	k := key(t)
	etp := etpOf(t)
	els := make(types.AuthorizationData, maxElements)
	for i := range els {
		els[i] = types.AuthorizationDataEntry{ADType: int32(1000 + i), ADData: make([]byte, maxElementData)}
	}
	raw := signedWith(t, etp, els, k, 3)
	if len(raw) <= MaxContainer {
		t.Fatalf("only %d bytes", len(raw))
	}
	if _, err := Verify(raw, etp, k, 3); !errors.Is(err, ErrMalformed) {
		t.Errorf("Verify: %v", err)
	}
	if _, err := Decode(raw); !errors.Is(err, ErrMalformed) {
		t.Errorf("Decode: %v", err)
	}
}
