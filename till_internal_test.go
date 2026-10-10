// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// RFC 4120 5.4.1: a till of 19700101000000Z asks for the longest ticket the
// realm allows. It is what Heimdal's kgetcred sends; v0.4.1 took it for a
// real end and issued a service ticket that had expired in 1970, which klist
// showed as >>>Expired<<<. MIT's kvno, this repository's judge, sends a real
// till and never saw it. The till goes over the wire here, so the epoch is
// the one DER decoding produces, not a value built in Go.
func TestATillOfTheEpochAsksForTheLongestTicket(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	n := now().UTC()
	tgtEnd := n.Add(5 * time.Hour).Truncate(time.Second)
	out, session := tgsWith(t, s, n.Add(-time.Minute), tgtEnd, time.Unix(0, 0).UTC(), false)
	var rep messages.TGSRep
	if err := rep.Unmarshal(out); err != nil {
		t.Fatalf("refused (code %d)", krbErrorCode(t, out))
	}
	if err := rep.DecryptEncPart(session); err != nil {
		t.Fatal(err)
	}
	end := rep.DecryptedEncPart.EndTime
	if !end.After(n) {
		t.Fatalf("the ticket ends %v: already expired", end)
	}
	// The longest the realm allows, and still no later than the TGT.
	if want := tgtEnd; !end.Equal(want) {
		t.Errorf("the ticket ends %v, want the TGT's end %v", end, want)
	}
}

// A till that has already passed is refused, not answered with a ticket that
// is expired on arrival: RFC 4120 3.1.3, KDC_ERR_NEVER_VALID.
func TestATillInThePastIsNeverValid(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	n := now().UTC()
	out, _ := tgsWith(t, s, n.Add(-time.Minute), n.Add(time.Hour), n.Add(-time.Hour), false)
	if got := krbErrorCode(t, out); got != errorcode.KDC_ERR_NEVER_VALID {
		t.Errorf("error code %d, want KDC_ERR_NEVER_VALID (%d)", got, errorcode.KDC_ERR_NEVER_VALID)
	}
}
