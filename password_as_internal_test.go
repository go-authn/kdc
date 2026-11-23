// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// go-authn/kdc#41: the AS exchange derives a key from a password the directory
// holds, so it is an explicit opt-in. Off, every AS-REQ is KDC_ERR_POLICY
// (RFC 4120 §7.5.9), before the principal is looked up.
func TestPasswordDerivedASIsRefusedByDefault(t *testing.T) {
	alice := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, alice)
	var logged []string
	s.cfg.AllowPasswordDerivedAS = false
	s.cfg.Logf = func(f string, a ...any) { logged = append(logged, f) }

	key, err := s.cfg.keyFor(alice)
	if err != nil {
		t.Fatal(err)
	}
	reqs := map[string][]byte{
		"no pre-auth":      asReq(t, "alice", []string{"krbtgt", testRealm}, nil),
		"with a timestamp": asReq(t, "alice", []string{"krbtgt", testRealm}, timestampPA(t, key, now())),
		"unknown person":   asReq(t, "nobody", []string{"krbtgt", testRealm}, nil),
	}
	for name, req := range reqs {
		out := s.handle(req)
		if got := errorCode(t, out); got != errorcode.KDC_ERR_POLICY {
			t.Errorf("%s: code %d, want KDC_ERR_POLICY (12)", name, got)
		}
		var e messages.KRBError
		if err := e.Unmarshal(out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(e.EText, "AllowPasswordDerivedAS") {
			t.Errorf("%s: the reason %q does not name the option", name, e.EText)
		}
	}
	if len(logged) == 0 || !strings.Contains(strings.Join(logged, "\n"), "AllowPasswordDerivedAS") {
		t.Errorf("the operator log does not name the option: %q", logged)
	}
}

// The zero Config is the safe one.
func TestPasswordDerivedASIsOffInTheZeroConfig(t *testing.T) {
	if (Config{}).AllowPasswordDerivedAS {
		t.Fatal("AllowPasswordDerivedAS must default to false")
	}
}

// Opted in, the same request gets a TGT.
func TestPasswordDerivedASAcceptsWhenOptedIn(t *testing.T) {
	alice := directory.NewIdentity("alice", directory.WithPassword("alicepw"))
	s := testServer(t, alice)
	if !s.cfg.AllowPasswordDerivedAS {
		t.Fatal("testServer should opt in")
	}
	key, err := s.cfg.keyFor(alice)
	if err != nil {
		t.Fatal(err)
	}
	var rep messages.ASRep
	if err := rep.Unmarshal(s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, timestampPA(t, key, now())))); err != nil {
		t.Fatalf("no TGT with the option on: %v", err)
	}
	if got := errorCode(t, s.handle(asReq(t, "alice", []string{"krbtgt", testRealm}, nil))); got != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		t.Errorf("opted in, no pre-auth: code %d, want PREAUTH_REQUIRED", got)
	}
}
