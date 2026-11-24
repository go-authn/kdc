package kdc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc"
)

// MIT krb5 is the oracle for KKDCP too: `kdc = https://host/KdcProxy` in
// krb5.conf makes its kinit and kvno speak [MS-KKDCP] (sendto_kdc.c,
// make_proxy_request), and `http_anchors` names the CA it trusts. The realm
// below is reachable ONLY through the proxy -- the krb5.conf names no UDP or
// TCP address -- and each test also counts the POSTs the handler saw, so a
// pass cannot be a client that went somewhere else.

// startProxied brings up a realm behind KKDCPHandler on TLS and writes the
// krb5.conf of a client that has no other way to reach it. It returns the
// number of POSTs served so far.
func startProxied(t *testing.T, cfg kdc.Config) (posts *atomic.Int64) {
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
	t.Cleanup(func() { srv.Close() })
	posts = new(atomic.Int64)
	h := srv.KKDCPHandler()
	mux := http.NewServeMux()
	mux.HandleFunc("/KdcProxy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		h.ServeHTTP(w, r)
	})
	cert, caPEM := selfSigned(t)
	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	port := u.Port()

	dir := t.TempDir()
	anchors := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(anchors, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "krb5.conf")
	// The braces on their own lines: see start in judge_test.go.
	text := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
[realms]
    %s = {
        kdc = https://localhost:%s/KdcProxy
        http_anchors = FILE:%s
    }
[domain_realm]
    localhost = %s
%s`, cfg.Realm, cfg.Realm, port, anchors, cfg.Realm, tlsPlugin())
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", conf)
	t.Setenv("KRB5CCNAME", "FILE:"+filepath.Join(dir, "ccache"))
	return posts
}

// tlsPlugin names MIT's k5tls module when the build was relocated: pkgx's
// macOS krb5 looks for it under the path it was built at (/Users/runner/...,
// "Could not find tls plugin module named 'k5tls'"), where it does not exist,
// so https KDCs fail with "Cannot contact any KDC". The module is in the pkgx
// tree; krb5.conf's [plugins] section points at it. KDC_K5TLS overrides.
func tlsPlugin() string {
	path := os.Getenv("KDC_K5TLS")
	if path == "" {
		home, _ := os.UserHomeDir()
		found, _ := filepath.Glob(filepath.Join(home, ".pkgx", "kerberos.org", "v*.*.*", "lib", "krb5", "plugins", "tls", "k5tls.so"))
		if len(found) == 0 {
			return ""
		}
		path = found[len(found)-1]
	}
	return fmt.Sprintf("[plugins]\n    tls = {\n        module = k5tls:%s\n    }\n", path)
}

// selfSigned makes a certificate for localhost and 127.0.0.1 that is its own CA.
func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// run is kinit's outcome in the terms the tests compare: it succeeded, or what
// it said.
func kinitOut(t *testing.T, who, pw string) (string, error) {
	t.Helper()
	cmd := exec.Command("pkgx", "+kerberos.org", "--", "kinit", who+"@"+realm)
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader(pw + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestMITKinitAndKvnoThroughTheProxy(t *testing.T) {
	requireMIT(t)
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	posts := startProxied(t, kdc.Config{People: people, Services: realmKeytab(t), AllowPasswordDerivedAS: true})

	if out, err := kinitOut(t, "alice", password); err != nil {
		t.Fatalf("kinit through the proxy: %v\n%s", err, out)
	}
	out, err := mit(t, "klist")
	if err != nil || !strings.Contains(out, "krbtgt/"+realm) {
		t.Fatalf("no TGT in the cache: %v\n%s", err, out)
	}
	// A TGS-REQ through the proxy gives the answer it gives on 88: a ticket
	// for the service at the key version of the keytab.
	out, err = mit(t, "kvno", service+"@"+realm)
	if err != nil {
		t.Fatalf("kvno through the proxy: %v\n%s", err, out)
	}
	if !strings.Contains(out, "kvno = 2") {
		t.Errorf("wrong key version:\n%s", out)
	}
	if n := posts.Load(); n < 2 {
		t.Errorf("the handler saw %d POST(s), want at least 2 (AS and TGS)", n)
	}
}

// Every refusal is the refusal port 88 gives, word for word: the realm is run
// once behind each transport and the client's message compared.
func TestMITRefusalsAreTheSameThroughTheProxyAndOn88(t *testing.T) {
	requireMIT(t)
	cases := []struct {
		name   string
		person *directory.Identity
		who    string
		pw     string
		want   string
	}{
		{"wrong password", directory.NewIdentity("alice", directory.WithPassword(password)), "alice", "not the password", "Password incorrect"},
		{"unknown principal", directory.NewIdentity("alice", directory.WithPassword(password)), "mallory", password, "not found in Kerberos database"},
		{"a person with no key", directory.NewIdentity("alice", directory.WithVerifier(func(string) error { return nil })), "alice", password, "null key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := kdc.Config{People: onePerson{c.person}, Services: realmKeytab(t), AllowPasswordDerivedAS: true}
			start(t, cfg)
			on88, err := kinitOut(t, c.who, c.pw)
			if err == nil {
				t.Fatalf("accepted on 88:\n%s", on88)
			}
			posts := startProxied(t, cfg)
			viaProxy, err := kinitOut(t, c.who, c.pw)
			if err == nil {
				t.Fatalf("accepted through the proxy:\n%s", viaProxy)
			}
			if !strings.Contains(on88, c.want) || !strings.Contains(viaProxy, c.want) {
				t.Errorf("want %q\n88:    %s\nproxy: %s", c.want, on88, viaProxy)
			}
			if on88 != viaProxy {
				t.Errorf("not the same words\n88:    %s\nproxy: %s", on88, viaProxy)
			}
			if posts.Load() == 0 {
				t.Error("the proxy saw no POST: the refusal did not come from it")
			}
		})
	}
}
