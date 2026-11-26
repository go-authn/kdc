// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// The fixtures are the credential caches and service keytabs of a real run of
// the matrix (SAMBA_INTEROP=1), one per KDC, with throwaway keys.
var fixtureCases = []struct {
	file  string // prefix in testdata/
	types []string
	pac   bool
}{
	{"go-authn_kdc-none", nil, false},
	{"MIT_krb5kdc-none", []string{"1[128]"}, true},
	{"Heimdal_kdc-none", []string{"1[512]"}, false},
}

func loadKT(t *testing.T, file string) *keytab.Keytab {
	t.Helper()
	var kt keytab.Keytab
	if err := kt.Unmarshal(fixture(t, file+".keytab")); err != nil {
		t.Fatal(err)
	}
	return &kt
}

func TestTicketTypesOfRealTickets(t *testing.T) {
	for _, tc := range fixtureCases {
		got, pac, err := TicketTypes(fixture(t, tc.file+".ccache"), loadKT(t, tc.file), "cifs/"+Host)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if pac != tc.pac || !reflect.DeepEqual(got, tc.types) {
			t.Errorf("%s: types %v pac %v, want %v %v", tc.file, got, pac, tc.types, tc.pac)
		}
	}
}

func TestTicketTypesRefusals(t *testing.T) {
	cc := fixture(t, "MIT_krb5kdc-none.ccache")
	kt := loadKT(t, "MIT_krb5kdc-none")
	for _, tc := range []struct {
		name    string
		ccache  []byte
		kt      *keytab.Keytab
		service string
		want    string
	}{
		{"not a ccache", []byte("junk"), kt, "cifs/" + Host, "ccache:"},
		{"another service", cc, kt, "cifs/other.test", "no service ticket in the credential cache"},
		{"another key", cc, loadKT(t, "go-authn_kdc-none"), "cifs/" + Host, "decrypting the ticket for cifs/" + Host + " with the service keytab"},
		{"a damaged ticket", damageTicket(t, cc), kt, "cifs/" + Host, "ticket:"},
	} {
		_, _, err := TicketTypes(tc.ccache, tc.kt, tc.service)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want it to contain %q", tc.name, err, tc.want)
		}
	}
}

// damageTicket breaks the first byte (the ASN.1 tag) of the service ticket.
func damageTicket(t *testing.T, cc []byte) []byte {
	t.Helper()
	var c credentials.CCache
	if err := c.Unmarshal(cc); err != nil {
		t.Fatal(err)
	}
	for _, cr := range c.Credentials {
		if strings.Join(cr.Server.PrincipalName.NameString, "/") == "cifs/"+Host {
			i := bytes.Index(cc, cr.Ticket)
			if i < 0 {
				t.Fatal("the ticket is not in the cache bytes")
			}
			out := bytes.Clone(cc)
			out[i] = 0
			return out
		}
	}
	t.Fatal("no service ticket in the fixture")
	return nil
}

func TestTicketTypesEmptyInputIsARefusalNotAPanic(t *testing.T) {
	_, _, err := TicketTypes(nil, keytab.New(), "cifs/"+Host)
	if err == nil || !strings.Contains(err.Error(), "ccache: decoder panicked") {
		t.Fatalf("error %v", err)
	}
}

func TestTicketOfRealKDCParses(t *testing.T) {
	var c credentials.CCache
	if err := c.Unmarshal(fixture(t, "go-authn_kdc-none.ccache")); err != nil {
		t.Fatal(err)
	}
	var tk messages.Ticket
	for _, cr := range c.Credentials {
		if strings.Join(cr.Server.PrincipalName.NameString, "/") == "cifs/"+Host {
			if err := tk.Unmarshal(cr.Ticket); err != nil {
				t.Fatal(err)
			}
		}
	}
	if tk.SName.NameString[0] != "cifs" {
		t.Fatalf("service name %v", tk.SName.NameString)
	}
}

// FuzzTicketTypes feeds untrusted bytes to the ccache, ticket and
// authorization-data decoders: they may refuse, never panic.
func FuzzTicketTypes(f *testing.F) {
	kt := keytab.New()
	for _, tc := range fixtureCases {
		cc, err := readFixture(tc.file + ".ccache")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(cc)
	}
	f.Add([]byte{})
	f.Add([]byte{5, 4, 0, 0})
	f.Fuzz(func(t *testing.T, cc []byte) {
		_, _, _ = TicketTypes(cc, kt, "cifs/"+Host)
	})
}

// FuzzHasPAC feeds untrusted authorization data (nested AD-IF-RELEVANT
// included) to HasPAC and Describe: they may refuse, never panic, and agree.
func FuzzHasPAC(f *testing.F) {
	pac := types.AuthorizationDataEntry{ADType: adWin2KPAC, ADData: []byte{1}}
	if w, err := ifRelevant(pac); err == nil {
		if b, err := asn1.Marshal(types.AuthorizationData{w}); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		var ad types.AuthorizationData
		if err := ad.Unmarshal(b); err != nil {
			return
		}
		ok, err := HasPAC(ad)
		if err == nil && ok && !slices.ContainsFunc(Describe(ad), func(s string) bool { return strings.Contains(s, "128") }) {
			t.Fatalf("HasPAC true but Describe %v shows no type 128", Describe(ad))
		}
	})
}
