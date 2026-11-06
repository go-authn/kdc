// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// noWalk is a Finder whose walk must never be taken: Identities fails the
// test. What Find answers is set per test.
type noWalk struct {
	t    *testing.T
	find func(string) (*directory.Identity, bool, error)
}

func (n noWalk) Identities() ([]*directory.Identity, error) {
	n.t.Error("Identities was called although the source is a Finder")
	return nil, errors.New("walked")
}
func (noWalk) Describe() string                 { return "finder" }
func (noWalk) Members(string) ([]string, error) { return nil, nil }
func (n noWalk) Find(name string) (*directory.Identity, bool, error) {
	return n.find(name)
}

func finderServer(t *testing.T, find func(string) (*directory.Identity, bool, error)) *Server {
	s := testServer(t, directory.NewIdentity("unused", directory.WithPassword("x")))
	s.cfg.People = noWalk{t: t, find: find}
	return s
}

// With a Finder the realm asks it, and a right password gets a TGT without the
// directory being walked, at the AS and at the TGS.
func TestAFinderIsAskedInsteadOfTheWalk(t *testing.T) {
	alice := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	var asked []string
	s := finderServer(t, func(name string) (*directory.Identity, bool, error) {
		asked = append(asked, name)
		if name == "alice" {
			return alice, true, nil
		}
		return nil, false, nil
	})
	key, err := s.cfg.keyFor(alice)
	if err != nil {
		t.Fatal(err)
	}
	var rep messages.ASRep
	if err := rep.Unmarshal(s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, timestampPA(t, key, now())))); err != nil {
		t.Fatalf("no TGT for alice through a Finder: %v", err)
	}
	if got := errorCode(t, s.handle(asReq(t, "nobody", []string{"krbtgt", testRealm}, nil))); got != errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN {
		t.Errorf("a name the Finder does not have: code %d, want C_PRINCIPAL_UNKNOWN (6)", got)
	}
	// The TGS checks the client is still there, through the Finder too.
	if out := s.handle(tgsAt(t, s, "alice", now(), 1)); !issued(t, out) {
		t.Errorf("TGS through a Finder: code %d, want a ticket", krbErrorCode(t, out))
	}
	if strings.Join(asked, ",") != "alice,nobody,alice" {
		t.Errorf("the Finder was asked %q", asked)
	}
}

// ⛔ A principal is case-sensitive. A source indexed by a folded name that
// hands back "Alice" for "alice" — or anybody else — is not believed: the
// realm compares the name it got.
func TestAFinderAnsweringAnotherNameIsNotBelieved(t *testing.T) {
	alice := directory.NewIdentity("Alice", directory.WithPassword("alicepw"))
	s := finderServer(t, func(string) (*directory.Identity, bool, error) { return alice, true, nil })
	if got := errorCode(t, s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, nil))); got != errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN {
		t.Errorf("Find(alice) answered Alice: code %d, want C_PRINCIPAL_UNKNOWN (6)", got)
	}
	// found without an identity is not somebody either.
	s = finderServer(t, func(string) (*directory.Identity, bool, error) { return nil, true, nil })
	if got := errorCode(t, s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, nil))); got != errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN {
		t.Errorf("found with a nil identity: code %d, want C_PRINCIPAL_UNKNOWN (6)", got)
	}
}

// A Finder that cannot read its source is an outage, as Identities failing is.
func TestAFinderErrorIsAnOutage(t *testing.T) {
	s := finderServer(t, func(string) (*directory.Identity, bool, error) {
		return nil, false, errors.New("the snapshot is older than max_age")
	})
	if got := errorCode(t, s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, nil))); got != errorcode.KDC_ERR_SVC_UNAVAILABLE {
		t.Errorf("Find failed: code %d, want SVC_UNAVAILABLE (29)", got)
	}
}
