// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/go-authn/kdc/internal/pac"
	"github.com/jcmturner/gokrb5/v8/types"
)

// MIT_VERIFY=1 runs the PAC through MIT's own krb5_kdc_verify_ticket in a
// container (interop/mitverify): an issuer that checks only its own signatures
// proves nothing, and Samba is no oracle for them (winbindd falls back to an
// unsigned decode).
func TestMITVerifiesThePACWeIssue(t *testing.T) {
	if os.Getenv("MIT_VERIFY") != "1" {
		t.Skip("set MIT_VERIFY=1 (needs docker): runs MIT krb5_kdc_verify_ticket on our PAC")
	}
	docker := func(args ...string) (string, error) {
		var out bytes.Buffer
		c := exec.Command("docker", args...)
		c.Stdout, c.Stderr = &out, &out
		c.Stdin = nil
		err := c.Run()
		return out.String(), err
	}
	if o, err := docker("build", "-q", "-t", "go-authn-mitverify", "interop/mitverify"); err != nil {
		t.Fatalf("docker build: %v\n%s", err, o)
	}

	alice := person(t, "alice", "1001", "1000", "staff")
	s, kt := pacServer(t, peopleList{alice}, &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}})
	tkt, svcKey := nfsTicket(t, s, kt)
	der, err := tkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	krbtgt, _, err := kt.GetEncryptionKey(types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", testRealm}}, testRealm, 0, defaultEtype)
	if err != nil {
		t.Fatal(err)
	}
	run := func(tgtKey []byte) (string, error) {
		return docker("run", "--rm", "go-authn-mitverify",
			hex.EncodeToString(der), hex.EncodeToString(svcKey), hex.EncodeToString(tgtKey),
			"alice@"+testRealm, "nfs/localhost@"+testRealm)
	}

	o, err := run(krbtgt.KeyValue)
	if err != nil || !strings.HasSuffix(strings.TrimSpace(o), "OK") {
		t.Fatalf("MIT refuses the PAC: %v\n%s", err, o)
	}
	for _, typ := range []uint32{pac.TypeLogonInfo, pac.TypeClientInfo, pac.TypeServerChecksum, pac.TypeKDCChecksum, pac.TypeTicketChecksum, pac.TypeFullChecksum, pac.TypeRequestorSID} {
		if !strings.Contains(o, "buffer "+strconv.FormatUint(uint64(typ), 10)+"\n") {
			t.Errorf("MIT does not see buffer %d:\n%s", typ, o)
		}
	}

	// The control: the same ticket under another krbtgt key must be refused,
	// or the verifier proved nothing.
	if o, err := run(make([]byte, 32)); err == nil {
		t.Fatalf("MIT accepted a PAC under the wrong KDC key:\n%s", o)
	}
}
