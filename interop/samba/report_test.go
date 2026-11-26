// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/types"
)

func TestDescribe(t *testing.T) {
	pac := types.AuthorizationDataEntry{ADType: adWin2KPAC, ADData: []byte{1}}
	wrapped, err := ifRelevant(pac)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := ifRelevant()
	if err != nil {
		t.Fatal(err)
	}
	got := Describe(types.AuthorizationData{wrapped, empty, {ADType: 512}})
	if want := []string{"1[128]", "1[]", "512"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Describe = %v, want %v", got, want)
	}
	bad := types.AuthorizationDataEntry{ADType: 1, ADData: []byte{0xff}}
	if got := Describe(types.AuthorizationData{bad}); !reflect.DeepEqual(got, []string{"1[undecodable]"}) {
		t.Fatalf("Describe(undecodable) = %v", got)
	}
}

func TestEvidence(t *testing.T) {
	log := "noise\nUnable to find PAC for alice\nmore noise\nSuccessful AuthZ: x\n"
	got := Evidence(log)
	if want := []string{"Unable to find PAC for alice", "Successful AuthZ: x"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Evidence = %v, want %v", got, want)
	}
	long := strings.Repeat("Successful AuthZ\n", 100)
	if n := len(Evidence(long)); n != 40 {
		t.Fatalf("Evidence kept %d lines, want the cap of 40", n)
	}
}

func TestLastCifsEnc(t *testing.T) {
	k := "Ticket cache\n  krbtgt/X@X\n\tEtype: a\n  cifs/h@X\n\tEtype: aes256\n"
	if got := lastCifsEnc(k); got != "Etype: aes256" {
		t.Fatalf("lastCifsEnc = %q", got)
	}
	if got := lastCifsEnc("nothing"); got != "" {
		t.Fatalf("lastCifsEnc(none) = %q", got)
	}
}

func TestTable(t *testing.T) {
	got := Table([]Result{
		{KDC: "A", KDCVersion: "1", PAC: true, TicketEnc: "e", SmbOK: true, Relaxation: "none"},
		{KDC: "B", KDCVersion: "2", Relaxation: "x", Err: "boom"},
	})
	want := "| KDC | version | PAC in service ticket | ticket enc | Samba accepts | Samba relaxation |\n|---|---|---|---|---|---|\n" +
		"| A | 1 | yes | e | yes | none |\n| B | 2 | no |  | error: boom | x |\n"
	if got != want {
		t.Fatalf("Table =\n%s\nwant\n%s", got, want)
	}
}
