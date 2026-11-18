// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// mintServer is a realm whose person has NO password: the case an AS-REQ
// answers KDC_ERR_NULL_KEY.
func mintServer(t *testing.T, callers ...string) *Server {
	t.Helper()
	id := directory.NewIdentity("alice@univ.example", directory.WithVerifier(func(string) error { return nil }))
	s := testServer(t, id)
	s.cfg.MintCallers = callers
	return s
}

func TestMintIsOffByDefault(t *testing.T) {
	s := mintServer(t)
	if _, err := s.Mint(MintRequest{Principal: "alice@univ.example"}); !errors.Is(err, ErrMintDisabled) {
		t.Fatalf("Mint with no callers configured: %v", err)
	}
	rec := httptest.NewRecorder()
	s.MintHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{"principal":"alice@univ.example"}`)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("handler with minting off: %d, want 404", rec.Code)
	}
}

// The control the whole feature rests on: the person has no key, so the AS
// path refuses, and the mint path gives a TGT the TGS honours -- also in
// Windows' form (RSA-MD5 authenticator checksum).
func TestMintedTGTBuysAServiceTicket(t *testing.T) {
	s := mintServer(t, "https://login.example.org")
	if got := errorCode(t, s.handle(asReq(t, "alice@univ.example", []string{"krbtgt", testRealm}, nil))); got == 0 {
		t.Fatal("no refusal for a person with no key")
	}

	raw, err := s.Mint(MintRequest{Principal: "alice@univ.example", LifetimeSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	var cred messages.KRBCred
	if err := cred.Unmarshal(raw); err != nil {
		t.Fatalf("not a KRB-CRED: %v", err)
	}
	if len(cred.Tickets) != 1 || cred.EncPart.EType != 0 {
		t.Fatalf("tickets %d, etype %d", len(cred.Tickets), cred.EncPart.EType)
	}
	// EncKrbCredPart is the cipher itself under etype 0 (RFC 4120 5.8.1).
	var part messages.EncKrbCredPart
	if err := part.Unmarshal(cred.EncPart.Cipher); err != nil {
		t.Fatalf("EncKrbCredPart: %v", err)
	}
	info := part.TicketInfo[0]
	for _, f := range []int{flags.Initial, flags.PreAuthent} {
		if !types.IsFlagSet(&info.Flags, f) {
			t.Errorf("flag %d not set", f)
		}
	}
	for _, f := range []int{flags.Renewable, flags.Forwardable, flags.Proxiable} {
		if types.IsFlagSet(&info.Flags, f) {
			t.Errorf("flag %d set though never granted", f)
		}
	}
	if d := info.EndTime.Sub(info.StartTime); d != time.Hour {
		t.Errorf("lifetime %v, want the 1h asked for", d)
	}
	if info.PName.NameString[0] != "alice@univ.example" || info.PRealm != testRealm {
		t.Errorf("principal %v@%s", info.PName.NameString, info.PRealm)
	}

	// Use it: a TGS-REQ signed as Windows signs it.
	body := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
		SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"nfs", "localhost"}},
		Till:  now().UTC().Add(time.Hour), Nonce: 3, EType: []int32{defaultEtype}}
	req := signedTGSReq(t, cred.Tickets[0], info.Key, info.PName, body, windowsChecksum)
	var rep messages.TGSRep
	if out := s.handle(req); rep.Unmarshal(out) != nil {
		t.Fatalf("the minted TGT bought nothing: error %d", krbErrorCode(t, out))
	}
}

func TestMintCapsAndRefusals(t *testing.T) {
	s := mintServer(t, "https://login.example.org")
	for _, c := range []struct {
		name string
		req  MintRequest
	}{
		{"an unknown person", MintRequest{Principal: "mallory@univ.example"}},
		{"a service principal", MintRequest{Principal: "nfs/localhost"}},
		{"an empty name", MintRequest{}},
		{"a name that splits", MintRequest{Principal: "alice@univ.example,root"}},
		{"under a minute", MintRequest{Principal: "alice@univ.example", LifetimeSeconds: 5}},
	} {
		if _, err := s.Mint(c.req); !errors.Is(err, ErrMintRefused) {
			t.Errorf("%s: %v, want a refusal", c.name, err)
		}
	}
	// Asking for a year gets the cap, not a year.
	raw, err := s.Mint(MintRequest{Principal: "alice@univ.example", LifetimeSeconds: 365 * 24 * 3600})
	if err != nil {
		t.Fatal(err)
	}
	var cred messages.KRBCred
	if err := cred.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	var part messages.EncKrbCredPart
	if err := part.Unmarshal(cred.EncPart.Cipher); err != nil {
		t.Fatal(err)
	}
	if d := part.TicketInfo[0].EndTime.Sub(part.TicketInfo[0].StartTime); d > MaxMintLifetime {
		t.Errorf("lifetime %v exceeds the cap %v", d, MaxMintLifetime)
	}
	// And a configured Lifetime below the cap wins.
	s.cfg.Lifetime = 2 * time.Hour
	raw, _ = s.Mint(MintRequest{Principal: "alice@univ.example"})
	if err := cred.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	_ = part.Unmarshal(cred.EncPart.Cipher)
	if d := part.TicketInfo[0].EndTime.Sub(part.TicketInfo[0].StartTime); d != 2*time.Hour {
		t.Errorf("lifetime %v, want Config.Lifetime 2h", d)
	}
}

// pki makes a CA and leaf certificates with URI names.
type pki struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPool *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca, k, pool}
}

func (p *pki) leaf(t *testing.T, uri string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"localhost"}, IPAddresses: nil}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestMintHandlerAuthenticatesTheCaller(t *testing.T) {
	s := mintServer(t, "https://login.example.org")
	p := newPKI(t)
	srv := httptest.NewUnstartedServer(s.MintHandler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{p.leaf(t, "", x509.ExtKeyUsageServerAuth)},
		ClientAuth:   tls.VerifyClientCertIfGiven, // a MISCONFIGURED listener: the handler must still refuse
		ClientCAs:    p.caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	post := func(cert *tls.Certificate) (int, []byte) {
		cfg := &tls.Config{RootCAs: p.caPool, ServerName: "localhost"}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		b, _ := json.Marshal(MintRequest{Principal: "alice@univ.example"})
		resp, err := c.Post(srv.URL, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}

	good := p.leaf(t, "https://login.example.org", x509.ExtKeyUsageClientAuth)
	other := p.leaf(t, "https://evil.example", x509.ExtKeyUsageClientAuth)
	bare := p.leaf(t, "", x509.ExtKeyUsageClientAuth)

	if code, body := post(&good); code != 200 {
		t.Fatalf("the listed caller: %d %s", code, body)
	} else if (&messages.KRBCred{}).Unmarshal(body) != nil {
		t.Error("the reply is not a KRB-CRED")
	}
	for name, c := range map[string]*tls.Certificate{"no certificate": nil, "an unlisted URI": &other, "no URI": &bare} {
		if code, _ := post(c); code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, code)
		}
	}

	// Plain HTTP, no TLS state at all.
	rec := httptest.NewRecorder()
	s.MintHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{"principal":"alice@univ.example"}`)))
	if rec.Code != http.StatusForbidden {
		t.Errorf("without TLS: %d, want 403", rec.Code)
	}
}
