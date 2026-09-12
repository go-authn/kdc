package kdc_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// This file puts MIT Kerberos in front of the realm rather than a client of
// my own. kinit and kvno read RFC 4120 independently, years earlier, and they
// refuse what they do not recognise.
//
// No MIT KDC is involved: the keytab is built here in Go, and the only thing
// borrowed is the CLIENT. That is the point — a realm judged by a client it
// did not write.
//
// KDC_REQUIRE_JUDGE=1 turns "MIT is not installed" from a skip into a failure.
// Every lane that runs these tests sets it: a differential test that can
// quietly not run is not a control.

const (
	realm    = "FLEET.TEST"
	password = "correct horse battery staple"
	service  = "nfs/localhost"
)

func mit(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("pkgx", append([]string{"+kerberos.org", "--"}, args...)...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func requireMIT(t *testing.T) {
	t.Helper()
	if _, err := mit(t, "klist", "-V"); err != nil {
		if os.Getenv("KDC_REQUIRE_JUDGE") != "" {
			t.Fatalf("KDC_REQUIRE_JUDGE is set but MIT Kerberos is not usable: %v", err)
		}
		t.Skip("no MIT Kerberos; install pkgx")
	}
}

// realmKeytab builds the keys a realm needs, in Go. A KDC needs krbtgt to sign
// its own tickets and a key per service to seal theirs.
func realmKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	for _, p := range []string{"krbtgt/" + realm, service} {
		if err := kt.AddEntry(p, realm, "a key nobody types", time.Now(), 2, 18); err != nil {
			t.Fatalf("keytab %s: %v", p, err)
		}
	}
	return kt
}

type onePerson struct{ id *directory.Identity }

func (o onePerson) Identities() ([]*directory.Identity, error) {
	return []*directory.Identity{o.id}, nil
}
func (o onePerson) Describe() string                 { return "one person, in this test" }
func (o onePerson) Members(string) ([]string, error) { return nil, nil }

// start brings up a realm on a free port and writes the krb5.conf a client
// needs to find it.
func start(t *testing.T, cfg kdc.Config) (confPath, ccache string) {
	t.Helper()
	if cfg.Realm == "" {
		cfg.Realm = realm
	}
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	srv, err := kdc.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeUDP(pc)
	go srv.ServeTCP(ln)
	t.Cleanup(func() { srv.Close() })

	dir := t.TempDir()
	confPath = filepath.Join(dir, "krb5.conf")
	// ⛔ The braces go on their own lines. MIT's profile parser silently
	// ignores a realm written as `X = { kdc = ... }` on one line, and kinit
	// then says "Cannot find KDC for realm" — a message about the realm, from
	// a failure about whitespace.
	conf := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
[realms]
    %s = {
        kdc = 127.0.0.1:%d
    }
[domain_realm]
    localhost = %s
`, cfg.Realm, cfg.Realm, port, cfg.Realm)
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	ccache = filepath.Join(dir, "ccache")
	t.Setenv("KRB5_CONFIG", confPath)
	t.Setenv("KRB5CCNAME", "FILE:"+ccache)
	return confPath, ccache
}

func TestMITClientGetsATGTAndAServiceTicket(t *testing.T) {
	requireMIT(t)
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	start(t, kdc.Config{People: people, Services: realmKeytab(t)})

	// kinit reads the password on stdin when it is not a terminal.
	cmd := exec.Command("pkgx", "+kerberos.org", "--", "kinit", "alice@"+realm)
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader(password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kinit: %v\n%s", err, out)
	}

	out, err := mit(t, "klist")
	if err != nil {
		t.Fatalf("klist: %v\n%s", err, out)
	}
	if !strings.Contains(out, "krbtgt/"+realm) {
		t.Fatalf("no TGT in the cache:\n%s", out)
	}

	// And the other half: a ticket to a service, which exercises TGS-REQ and
	// never touches the password again.
	out, err = mit(t, "kvno", service+"@"+realm)
	if err != nil {
		t.Fatalf("kvno: %v\n%s", err, out)
	}
	// ⛔ The key version must be the one in the keytab. Stamping zero is
	// easy and leaves an acceptor holding several versions to guess which
	// one sealed the ticket.
	if !strings.Contains(out, "kvno = 2") {
		t.Errorf("kvno reported the wrong key version:\n%s", out)
	}
	t.Logf("MIT kinit and kvno were served by this realm: %s", strings.TrimSpace(out))
}

func TestAWrongPasswordIsRefused(t *testing.T) {
	requireMIT(t)
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	start(t, kdc.Config{People: people, Services: realmKeytab(t)})

	cmd := exec.Command("pkgx", "+kerberos.org", "--", "kinit", "alice@"+realm)
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader("not the password\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a wrong password was accepted:\n%s", out)
	}
	if !strings.Contains(string(out), "Password incorrect") {
		t.Errorf("kinit said something else:\n%s", out)
	}
}

func TestAnUnknownPrincipalIsRefused(t *testing.T) {
	requireMIT(t)
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	start(t, kdc.Config{People: people, Services: realmKeytab(t)})

	cmd := exec.Command("pkgx", "+kerberos.org", "--", "kinit", "mallory@"+realm)
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("an unknown principal was accepted:\n%s", out)
	}
	// The code matters more than the text: this one makes kinit stop rather
	// than prompt again.
	if !strings.Contains(string(out), "not found in Kerberos database") {
		t.Errorf("kinit said something else:\n%s", out)
	}
}

func TestAVerifierBackedDirectoryCannotServeARealm(t *testing.T) {
	requireMIT(t)
	// ⛔ A KDC must DECRYPT the client's pre-authentication with this
	// person's key. "Is this the right password" does not produce one, so a
	// bind-backed source cannot back a realm however well it authenticates
	// elsewhere. The refusal has to be legible: an operator who configured
	// ldapdir here needs to be told that, not "password incorrect".
	people := onePerson{directory.NewIdentity("alice",
		directory.WithVerifier(func(string) error { return nil }))}
	start(t, kdc.Config{People: people, Services: realmKeytab(t)})

	cmd := exec.Command("pkgx", "+kerberos.org", "--", "kinit", "alice@"+realm)
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a verifier-backed realm issued a ticket:\n%s", out)
	}
	if !strings.Contains(string(out), "null key") {
		t.Errorf("kinit said something else:\n%s", out)
	}
}

// kinitAs runs kinit and returns its output when it FAILS, empty when it
// succeeds — the shape the callers want.
func kinitAs(t *testing.T, who, pw string) string {
	t.Helper()
	cmd := exec.Command("pkgx", "+kerberos.org", "--", "kinit", who+"@"+realm)
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader(pw + "\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return ""
	}
	return string(out)
}
