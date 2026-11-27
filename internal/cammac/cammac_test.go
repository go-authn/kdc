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
