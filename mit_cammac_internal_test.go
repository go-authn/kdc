// SPDX-License-Identifier: BSD-3-Clause

package kdc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/kdc/internal/cammac"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// MIT_CAMMAC=1 asks MIT's own krb5kdc, in a container (interop/mitcammac),
// whether it reads the CAMMAC this package writes into a ticket-granting ticket.
//
// The container's krbtgt key is ours (the same password, so the same AES-256
// key, kvno 2). The test seals TGTs with it, as the AS and the Mint do, and
// sends a TGS-REQ for four services whose MIT principals carry a require_auth
// string: MIT issues the ticket only when it has parsed our CAMMAC, verified
// the kdc-verifier against the ticket, and found the indicator in it (RFC 8129
// section 3; krb5 src/kdc/kdc_authdata.c get_auth_indicators and
// src/kdc/cammac.c cammac_check_kdcver). A container MIT cannot verify is
// dropped without an error, so every positive case has a negative twin: the
// same request with the container damaged must get KDC_ERR_POLICY, or the
// positive proved nothing.
func TestMITAcceptsTheCAMMACWeIssue(t *testing.T) {
	if os.Getenv("MIT_CAMMAC") != "1" {
		t.Skip("set MIT_CAMMAC=1 (needs docker): sends our TGTs to MIT krb5kdc")
	}
	addr := startMITKDC(t)

	kt := keytab.New()
	for _, e := range []struct {
		name, pw string
		kvno     uint8
	}{
		{"krbtgt/" + testRealm, "krbtgtpw", 2},
		{"svc/plain", "svcpw", 1}, {"svc/passkey", "svcpw", 1}, {"svc/machine", "svcpw", 1}, {"svc/either", "svcpw", 1},
	} {
		if err := kt.AddEntry(e.name, testRealm, e.pw, time.Now(), e.kvno, 18); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(Config{Realm: testRealm, People: peopleList{person(t, "alice", "1001", "1000")}, Services: kt,
		Logf: t.Logf, AllowPasswordDerivedAS: true, PAC: &PAC{DomainSID: testDomainSID}})
	if err != nil {
		t.Fatal(err)
	}
	krbtgt := s.krbtgtName()
	tgtKey, kvno, err := kt.GetEncryptionKey(krbtgt, testRealm, 0, defaultEtype)
	if err != nil || kvno != 2 {
		t.Fatalf("krbtgt key: kvno %d, %v", kvno, err)
	}
	alice := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{"alice"}}

	// seal makes a TGT through the code the AS and the Mint use; damage then
	// opens it with the krbtgt key, changes it and seals it again around the
	// SAME container (the checksum is not redone).
	seal := func(c cammac.Claims, damage func(*messages.EncTicketPart)) (messages.Ticket, types.EncryptionKey) {
		t.Helper()
		n := now().UTC().Truncate(time.Second)
		fl := types.NewKrbFlags()
		types.SetFlag(&fl, flags.Initial)
		types.SetFlag(&fl, flags.PreAuthent)
		tkt, session, err := s.newTGT(alice, fl, n, n, n.Add(time.Hour), c)
		if err != nil {
			t.Fatal(err)
		}
		if damage == nil {
			return tkt, session
		}
		if err := tkt.Decrypt(tgtKey); err != nil {
			t.Fatal(err)
		}
		etp := tkt.DecryptedEncPart
		damage(&etp)
		b, err := marshalASN1(etp)
		if err != nil {
			t.Fatal(err)
		}
		tkt.EncPart, err = encryptWith(asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart), tgtKey, keyusage.KDC_REP_TICKET, kvno)
		if err != nil {
			t.Fatal(err)
		}
		return tkt, session
	}
	// buy sends the TGS-REQ and returns the error code, or 0 and the service
	// ticket, decrypted.
	buy := func(tkt messages.Ticket, session types.EncryptionKey, svc string) (int32, messages.Ticket) {
		t.Helper()
		body := messages.KDCReqBody{KDCOptions: types.NewKrbFlags(), Realm: testRealm,
			SName: types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"svc", svc}},
			Till:  now().UTC().Add(30 * time.Minute).Truncate(time.Second), Nonce: 11, EType: []int32{defaultEtype}}
		out, err := mitExchange(addr, signedTGSReq(t, tkt, session, alice, body, bodyChecksum(t, session)))
		if err != nil {
			t.Fatalf("MIT KDC: %v", err)
		}
		var e messages.KRBError
		if e.Unmarshal(out) == nil {
			t.Logf("svc/%s: KRB-ERROR %d %s", svc, e.ErrorCode, e.EText)
			return e.ErrorCode, messages.Ticket{}
		}
		var rep messages.TGSRep
		if err := rep.Unmarshal(out); err != nil {
			t.Fatalf("neither a KRB-ERROR nor a TGS-REP: %v", err)
		}
		key, _, err := kt.GetEncryptionKey(rep.Ticket.SName, testRealm, 0, defaultEtype)
		if err != nil {
			t.Fatal(err)
		}
		if err := rep.Ticket.Decrypt(key); err != nil {
			t.Fatalf("the ticket MIT issued does not open with the service key: %v", err)
		}
		t.Logf("svc/%s: ticket issued", svc)
		return 0, rep.Ticket
	}

	passkey := cammac.Claims{Methods: []string{cammac.MethodPasskey}, UID: 1001}
	machine := cammac.Claims{Methods: []string{cammac.MethodMachine}, UID: 1001}
	const policy = errorcode.KDC_ERR_POLICY

	// Readiness: the container accepts connections before krb5kdc listens.
	for i := 0; ; i++ {
		tkt, sk := seal(cammac.Claims{UID: 1001}, nil)
		code, _ := buy(tkt, sk, "plain")
		if code == 0 {
			break
		}
		if i == 10 {
			t.Fatalf("MIT refuses a TGT of ours for a service with no require_auth: code %d", code)
		}
		time.Sleep(time.Second)
	}

	for _, c := range []struct {
		name   string
		claims cammac.Claims
		damage func(*messages.EncTicketPart)
		svc    string
		want   int32 // 0: a ticket
	}{
		// What MIT must accept: our container, indicator and private uid element.
		{"passkey TGT, service wants passkey", passkey, nil, "passkey", 0},
		{"passkey TGT, service wants passkey or machine", passkey, nil, "either", 0},
		{"machine TGT, service wants machine", machine, nil, "machine", 0},
		{"machine TGT, service wants passkey or machine", machine, nil, "either", 0},
		// The wrong or no indicator: KDC_ERR_POLICY.
		{"passkey TGT, service wants machine", passkey, nil, "machine", policy},
		{"machine TGT, service wants passkey", machine, nil, "passkey", policy},
		{"no indicator (password logon), service wants passkey", cammac.Claims{UID: 1001}, nil, "passkey", policy},
		{"no indicator (password logon), service wants passkey or machine", cammac.Claims{UID: 1001}, nil, "either", policy},
		{"no indicator (password logon), service wants nothing", cammac.Claims{UID: 1001}, nil, "plain", 0},
		// Tampering: the same request as the first row, the container damaged.
		{"indicator rewritten to machine, MAC kept; service wants machine", passkey, func(e *messages.EncTicketPart) {
			flipIndicator(t, e, "passkey", "machine")
		}, "machine", policy},
		{"indicator rewritten to machine, MAC kept; service wants passkey", passkey, func(e *messages.EncTicketPart) {
			flipIndicator(t, e, "passkey", "machine")
		}, "passkey", policy},
		{"ticket changed after sealing (end time); service wants passkey", passkey, func(e *messages.EncTicketPart) {
			e.EndTime = e.EndTime.Add(-time.Minute)
		}, "passkey", policy},
		{"ticket changed after sealing (flags); service wants passkey", passkey, func(e *messages.EncTicketPart) {
			e.Flags = types.NewKrbFlags()
		}, "passkey", policy},
		{"container dropped; service wants passkey", passkey, func(e *messages.EncTicketPart) {
			e.AuthorizationData = nil
		}, "passkey", policy},
		{"damaged container, service wants nothing", passkey, func(e *messages.EncTicketPart) {
			flipIndicator(t, e, "passkey", "machine")
		}, "plain", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			tkt, sk := seal(c.claims, c.damage)
			code, st := buy(tkt, sk, c.svc)
			if code != c.want {
				t.Fatalf("service svc/%s: error code %d, want %d", c.svc, code, c.want)
			}
			if c.want != 0 || c.damage != nil || len(c.claims.Methods) == 0 {
				return
			}
			// MIT wrote the indicator it verified into the service ticket's own
			// CAMMAC: it read the string we wrote.
			var ad []byte
			for _, a := range st.DecryptedEncPart.AuthorizationData {
				ad = append(ad, a.ADData...)
			}
			if !bytes.Contains(ad, []byte(c.claims.Methods[0])) {
				t.Errorf("the service ticket does not carry %q: %x", c.claims.Methods[0], ad)
			}
		})
	}
}

// flipIndicator rewrites one indicator to another of the same length inside
// the container, leaving the verifier as it was.
func flipIndicator(t *testing.T, e *messages.EncTicketPart, from, to string) {
	t.Helper()
	if len(from) != len(to) {
		t.Fatal("the rewrite must keep the length")
	}
	n := 0
	for i := range e.AuthorizationData {
		d := e.AuthorizationData[i].ADData
		n += bytes.Count(d, []byte(from))
		e.AuthorizationData[i].ADData = bytes.ReplaceAll(d, []byte(from), []byte(to))
	}
	if n != 1 {
		t.Fatalf("found %q %d times in the ticket's authorization data", from, n)
	}
}

// mitExchange sends one request to a KDC over TCP (RFC 4120 7.2.2).
func mitExchange(addr string, req []byte) ([]byte, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	msg := binary.BigEndian.AppendUint32(nil, uint32(len(req)))
	if _, err := c.Write(append(msg, req...)); err != nil {
		return nil, err
	}
	var l [4]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("reply of %d bytes", n)
	}
	out := make([]byte, n)
	_, err = io.ReadFull(c, out)
	return out, err
}

// startMITKDC builds interop/mitcammac, runs it and returns host:port of its
// TCP listener. The container is removed with the test.
func startMITKDC(t *testing.T) string {
	t.Helper()
	docker := func(args ...string) (string, error) {
		var out bytes.Buffer
		c := exec.Command("docker", args...)
		c.Stdout, c.Stderr = &out, &out
		c.Stdin = nil
		err := c.Run()
		return out.String(), err
	}
	if o, err := docker("build", "-q", "-t", "go-authn-mitcammac", "interop/mitcammac"); err != nil {
		t.Fatalf("docker build: %v\n%s", err, o)
	}
	name := fmt.Sprintf("go-authn-mitcammac-%d", os.Getpid())
	if o, err := docker("run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::88/tcp", "go-authn-mitcammac"); err != nil {
		t.Fatalf("docker run: %v\n%s", err, o)
	}
	t.Cleanup(func() {
		if o, err := docker("logs", name); err == nil {
			t.Logf("krb5kdc log:\n%s", o)
		}
		_, _ = docker("rm", "-f", name)
	})
	o, err := docker("port", name, "88/tcp")
	if err != nil {
		t.Fatalf("docker port: %v\n%s", err, o)
	}
	addr, _, _ := strings.Cut(strings.TrimSpace(o), "\n")
	if addr == "" {
		t.Fatalf("no port in %q", o)
	}
	return addr
}
