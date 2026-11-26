// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"testing"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestHasPAC(t *testing.T) {
	pac := types.AuthorizationDataEntry{ADType: adWin2KPAC, ADData: []byte{1}}
	other := types.AuthorizationDataEntry{ADType: 9, ADData: []byte{1}}
	wrapped, err := ifRelevant(pac)
	if err != nil {
		t.Fatal(err)
	}
	wrappedOther, err := ifRelevant(other)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ad   types.AuthorizationData
		want bool
	}{
		{"none", nil, false},
		{"a bare PAC", types.AuthorizationData{pac}, true},
		{"a PAC inside AD-IF-RELEVANT", types.AuthorizationData{wrapped}, true},
		{"another type", types.AuthorizationData{other}, false},
		{"another type inside AD-IF-RELEVANT", types.AuthorizationData{wrappedOther}, false},
		{"a PAC after other entries", types.AuthorizationData{other, wrappedOther, wrapped}, true},
	} {
		got, err := HasPAC(tc.ad)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := HasPAC(types.AuthorizationData{{ADType: 1, ADData: []byte("not asn.1")}}); err == nil {
		t.Error("an AD-IF-RELEVANT that does not decode was read as an answer")
	}
}

func TestTicketTypesRefusesGarbage(t *testing.T) {
	if _, _, err := TicketTypes([]byte("not a ccache"), keytab.New(), "cifs/x"); err == nil {
		t.Fatal("a garbage credential cache was accepted")
	}
}
