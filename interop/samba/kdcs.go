// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// A KDC is one of the three issuers in front of the same Samba.
type KDC interface {
	Name() string
	// Start brings the realm up and returns what Samba needs. Stop undoes it.
	Start(ctx context.Context) (Env, error)
	Version(ctx context.Context) string
	Stop()
}

// ---- go-authn/kdc, in the test process, reached from the containers ---------

type onlyOne struct{ id *directory.Identity }

func (o onlyOne) Identities() ([]*directory.Identity, error) {
	return []*directory.Identity{o.id}, nil
}
func (o onlyOne) Describe() string                 { return "one person" }
func (o onlyOne) Members(string) ([]string, error) { return nil, nil }

// GoKDC serves go-authn/kdc (this checkout) from the test process; the
// containers reach it as host.docker.internal.
type GoKDC struct {
	Realm string
	srv   *kdc.Server

	// etype and listen default to aes256-cts-hmac-sha1-96 (18) and
	// 0.0.0.0:0; tests set them to reach the refusals.
	etype  int32
	listen string

	// PAC makes the KDC put a PAC in the ticket for cifs/Host, for a Samba
	// that insists on one (a member server). The default issues none.
	PAC bool
}

// PACDomainSID is the domain SID the PAC row gives both the KDC (its config)
// and Samba (`net setdomainsid`): LOGON_INFO's domain must be Samba's own.
const PACDomainSID = "S-1-5-21-1111111111-2222222222-3333333333"

// newAttributes is a variable so a test can make it refuse: its input is
// constant, so nothing else can.
var newAttributes = directory.NewAttributes

func (g *GoKDC) Name() string {
	if g.PAC {
		return "go-authn/kdc (PAC)"
	}
	return "go-authn/kdc"
}

func (g *GoKDC) Version(context.Context) string { return "this checkout" }

// throwawayKeys derives the KDC's keytab (krbtgt and cifs) and Samba's (cifs
// only, marshalled) from throwaway strings, kvno 1. The key of cifs/Host is
// the one thing Samba and the KDC share.
func throwawayKeys(realm string, etype int32) (all *keytab.Keytab, forSamba []byte, err error) {
	all, only := keytab.New(), keytab.New()
	for _, p := range []string{"krbtgt/" + realm, "cifs/" + Host} {
		for _, kt := range []*keytab.Keytab{all, only} {
			if kt == only && p != "cifs/"+Host {
				continue
			}
			if err := kt.AddEntry(p, realm, "throwaway key of "+p, time.Now(), 1, etype); err != nil {
				return nil, nil, fmt.Errorf("key of %s: %w", p, err)
			}
		}
	}
	forSamba, err = only.Marshal()
	return all, forSamba, err
}

func (g *GoKDC) Start(ctx context.Context) (Env, error) {
	etype, listen := g.etype, g.listen
	if etype == 0 {
		etype = 18 // the one etype this KDC issues
	}
	if listen == "" {
		listen = "0.0.0.0:0"
	}
	all, kt, err := throwawayKeys(g.Realm, etype)
	if err != nil {
		return Env{}, err
	}
	opts := []directory.Option{directory.WithPassword(Pass)}
	cfg := kdc.Config{Realm: g.Realm, Services: all, AllowPasswordDerivedAS: true}
	if g.PAC {
		a, err := newAttributes(
			directory.Attribute{Name: "uidNumber", Values: []string{"1001"}},
			directory.Attribute{Name: "gidNumber", Values: []string{"1000"}})
		if err != nil {
			return Env{}, err
		}
		opts = append(opts, directory.WithAttributes(a))
		cfg.PAC = &kdc.PAC{DomainSID: PACDomainSID, Services: []string{"cifs/" + Host}}
	}
	cfg.People = onlyOne{directory.NewIdentity(User, opts...)}
	srv, err := kdc.New(cfg)
	if err != nil {
		return Env{}, fmt.Errorf("kdc.New: %w", err)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return Env{}, err
	}
	g.srv = srv
	go func() {
		// A throwaway KDC of a test harness: a panic inside it must not take
		// the test binary down unannounced, it is reported and Start's caller
		// sees the failed exchange.
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "go-authn/kdc server panicked: %v\n", r)
			}
		}()
		_ = srv.ServeTCP(ln)
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return Env{Realm: g.Realm, KDC: fmt.Sprintf("host.docker.internal:%d", port), Keytab: kt}, nil
}

func (g *GoKDC) Stop() {
	if g.srv != nil {
		_ = g.srv.Close()
	}
}

// ---- MIT krb5kdc, in its own container ---------------------------------------

type MITKDC struct {
	Realm string
	node  Node
}

func (m *MITKDC) Name() string { return "MIT krb5kdc" }

func (m *MITKDC) Version(ctx context.Context) string {
	o, _ := m.node.Run(ctx, nil, "dpkg-query", "-W", "-f=${Package} ${Version}", "krb5-kdc")
	return o.String()
}

const mitHost = "mit-kdc.interop.test"

func (m *MITKDC) Start(ctx context.Context) (Env, error) {
	v, err := StartNode(ctx, "interop-mit", "mit", mitHost)
	if err != nil {
		return Env{}, err
	}
	m.node = v
	kdcConf := fmt.Sprintf("[kdcdefaults]\n  kdc_ports = 88\n  kdc_tcp_ports = 88\n\n[realms]\n  %s = {\n    database_name = /var/lib/krb5kdc/principal\n    acl_file = /etc/krb5kdc/kadm5.acl\n    key_stash_file = /etc/krb5kdc/stash\n    max_life = 10h 0m 0s\n  }\n", m.Realm)
	// krb5.conf first: the KDC tools read the realm from it.
	if err := v.WriteFile(ctx, "/etc/krb5.conf", "644", []byte(krb5Conf(m.Realm, "127.0.0.1"))); err != nil {
		return Env{}, err
	}
	if err := v.WriteFile(ctx, "/etc/krb5kdc/kdc.conf", "644", []byte(kdcConf)); err != nil {
		return Env{}, err
	}
	if _, err := v.Must(ctx, []byte("master-"+Pass+"\nmaster-"+Pass+"\n"), "kdb5_util", "create", "-s", "-r", m.Realm); err != nil {
		return Env{}, err
	}
	script := fmt.Sprintf("addprinc -pw %s %s@%s\naddprinc -randkey cifs/%s@%s\nktadd -k /tmp/mit-cifs.keytab cifs/%s@%s\n",
		Pass, User, m.Realm, Host, m.Realm, Host, m.Realm)
	if o, err := v.Must(ctx, []byte(script), "kadmin.local"); err != nil || strings.Contains(o.String(), "rror") {
		return Env{}, fmt.Errorf("kadmin.local: %v %s", err, o)
	}
	if err := v.Spawn(ctx, "krb5kdc", "-n"); err != nil {
		return Env{}, err
	}
	kt, err := v.ReadFile(ctx, "/tmp/mit-cifs.keytab")
	if err != nil {
		return Env{}, err
	}
	return Env{Realm: m.Realm, KDC: mitHost, Keytab: kt}, nil
}

func (m *MITKDC) Stop() { m.node.Remove() }

// ---- Heimdal kdc, in its own container (the packages conflict) ---------------

type HeimdalKDC struct {
	Realm string
	node  Node
}

func (h *HeimdalKDC) Name() string { return "Heimdal kdc" }

func (h *HeimdalKDC) Version(ctx context.Context) string {
	o, _ := h.node.Run(ctx, nil, "dpkg-query", "-W", "-f=${Package} ${Version}", "heimdal-kdc")
	return o.String()
}

const heimdalHost = "heimdal-kdc.interop.test"

func (h *HeimdalKDC) Start(ctx context.Context) (Env, error) {
	v, err := StartNode(ctx, "interop-heimdal", "heimdal", heimdalHost)
	if err != nil {
		return Env{}, err
	}
	h.node = v
	if _, err := v.Must(ctx, nil, "kstash", "--random-key"); err != nil {
		return Env{}, err
	}
	script := fmt.Sprintf("init --realm-max-ticket-life=unlimited --realm-max-renewable-life=unlimited %s\nadd --password=%s --use-defaults %s@%s\nadd --random-key --use-defaults cifs/%s@%s\next_keytab -k /tmp/heimdal-cifs.keytab cifs/%s@%s\n",
		h.Realm, Pass, User, h.Realm, Host, h.Realm, Host, h.Realm)
	if o, err := v.Must(ctx, []byte(script), "kadmin.heimdal", "-l"); err != nil || strings.Contains(o.String(), "rror") {
		return Env{}, fmt.Errorf("kadmin.heimdal -l: %v %s", err, o)
	}
	if err := v.Spawn(ctx, "/usr/lib/heimdal-servers/kdc", "--config-file=/etc/heimdal-kdc/kdc.conf"); err != nil {
		return Env{}, err
	}
	kt, err := v.ReadFile(ctx, "/tmp/heimdal-cifs.keytab")
	if err != nil {
		return Env{}, err
	}
	return Env{Realm: h.Realm, KDC: heimdalHost, Keytab: kt}, nil
}

func (h *HeimdalKDC) Stop() { h.node.Remove() }
