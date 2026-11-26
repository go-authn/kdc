package automount

import (
	"context"
	"fmt"
	"strings"
)

// KDC is one Kerberos KDC flavor, running in its own container.
type KDC struct {
	Name      string // "mit", "heimdal"
	Container string
	IP        string
	Pkgs      string
	// Tag is the recorder tag of the files this flavor installs.
	Tag string

	conf    func() (path, content string)
	extra   map[string]string // more files, path -> content
	create  string            // script that creates the realm database
	service string            // systemd unit
	log     string            // KDC log file
	add     func(name, pass string) string
	ktadd   func(keytab, name string) string
	maxlife func(name, life string) string
}

// Node is the container's node.
func (k KDC) Node() Node { return LXC(k.Container) }

// AddScript is the script that creates a principal; pass == "" makes a random key.
func (k KDC) AddScript(name, pass string) string { return k.add(name, pass) }

// KeytabScript is the script that writes the keys of a principal to a keytab.
func (k KDC) KeytabScript(keytab, name string) string { return k.ktadd(keytab, name) }

// MaxLifeScript sets the maximum ticket life of a principal.
func (k KDC) MaxLifeScript(name, life string) string { return k.maxlife(name, life) }

// LogCmd is the command that prints the KDC's log, where each AS-REQ names the
// client principal. MIT's krb5kdc, as Debian starts it, writes to the journal
// whatever [logging] says, so its log is the unit's journal.
func (k KDC) LogCmd() string {
	if k.log == "" {
		return "journalctl -u " + k.service + " --no-pager -o cat"
	}
	return "cat " + Quote(k.log)
}

// MIT is MIT krb5 (krb5-kdc) as Debian 13 ships it.
func MIT() KDC {
	return KDC{
		Name: "mit", Container: "kdc-mit", IP: MITIP, Tag: "mit",
		Pkgs:    "krb5-kdc krb5-admin-server",
		conf:    func() (string, string) { return "/etc/krb5kdc/kdc.conf", MITKDCConf() },
		extra:   map[string]string{"/etc/krb5kdc/kadm5.acl": "*/admin@POC.TEST *\n"},
		create:  "test -f /var/lib/krb5kdc/principal || kdb5_util create -s -r POC.TEST -P masterkey-poc",
		service: "krb5-kdc",
		add: func(n, p string) string {
			if p == "" {
				return fmt.Sprintf("kadmin.local -q %s", Quote("addprinc -randkey "+n))
			}
			return fmt.Sprintf("kadmin.local -q %s", Quote("addprinc -pw "+p+" "+n))
		},
		ktadd: func(f, n string) string {
			return fmt.Sprintf("rm -f %s; kadmin.local -q %s", Quote(f), Quote("ktadd -k "+f+" "+n))
		},
		maxlife: func(n, life string) string {
			return fmt.Sprintf("kadmin.local -q %s", Quote(`modprinc -maxlife "`+life+`" `+n))
		},
	}
}

// Heimdal is Heimdal (heimdal-kdc) as Debian 13 ships it.
func Heimdal() KDC {
	return KDC{
		Name: "heimdal", Container: "kdc-heimdal", IP: HeimdalIP, Tag: "heimdal",
		Pkgs:    "heimdal-kdc heimdal-clients",
		conf:    func() (string, string) { return "/etc/krb5.conf", HeimdalKRB5Conf() },
		create:  "mkdir -p /var/lib/heimdal-kdc && (test -f /var/lib/heimdal-kdc/heimdal.db || kadmin -l init --realm-max-ticket-life=unlimited --realm-max-renewable-life=unlimited POC.TEST)",
		service: "heimdal-kdc", log: "/var/log/heimdal-kdc.log",
		add: func(n, p string) string {
			if p == "" {
				return fmt.Sprintf("kadmin -l add --random-key --use-defaults %s", Quote(n))
			}
			return fmt.Sprintf("kadmin -l add --password=%s --use-defaults %s", Quote(p), Quote(n))
		},
		ktadd: func(f, n string) string {
			return fmt.Sprintf("rm -f %s; kadmin -l ext_keytab -k %s %s", Quote(f), Quote(f), Quote(n))
		},
		maxlife: func(n, life string) string {
			return fmt.Sprintf("kadmin -l modify --max-ticket-life=%s %s", Quote(life), Quote(n))
		},
	}
}

// Principals the KDC must know: name and password ("" = random key).
func Principals() []struct{ Name, Pass string } {
	p := []struct{ Name, Pass string }{
		{"cifs/" + SambaFQDN, ""},
		{"root/" + ClientFQDN, ""},
		{"svc-partage", ""},
	}
	for _, u := range Users {
		p = append(p, struct{ Name, Pass string }{u.Name, u.Pass})
	}
	return p
}

// Setup installs the KDC in its container, creates the realm and the
// principals, and starts it. It is idempotent.
func (k KDC) Setup(ctx context.Context, l *Lab) error {
	n := k.Node()
	old := l.Tag
	l.Tag = k.Tag
	defer func() { l.Tag = old }()
	if _, err := l.Must(ctx, n, "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "+k.Pkgs+" >/tmp/apt-kdc.log 2>&1 || (tail -20 /tmp/apt-kdc.log; exit 1)"); err != nil {
		return err
	}
	p, c := k.conf()
	if err := l.Put(ctx, n, p, "644", "0:0", c); err != nil {
		return err
	}
	for path, content := range k.extra {
		if err := l.Put(ctx, n, path, "644", "0:0", content); err != nil {
			return err
		}
	}
	trunc := ""
	if k.log != "" {
		trunc = "; : > " + Quote(k.log)
	}
	if _, err := l.Must(ctx, n, "set -e; "+k.create+trunc); err != nil {
		return err
	}
	for _, pr := range Principals() {
		// kadmin.local fails on an existing principal: that is the idempotence.
		o, err := l.Sh(ctx, n, k.add(pr.Name, pr.Pass))
		if err != nil {
			return err
		}
		if o.Code != 0 && !containsAny(o.String(), "already exists", "Duplicate") {
			return fmt.Errorf("add %s: %s", pr.Name, o)
		}
	}
	_, err := l.Must(ctx, n, "systemctl enable "+k.service+" >/dev/null 2>&1; systemctl restart "+k.service+"; sleep 1; systemctl is-active "+k.service)
	return err
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
