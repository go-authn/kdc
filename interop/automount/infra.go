package automount

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// HostPackages are installed on the VM: the Proxmox host (lxc) and the client
// (cifs-utils, keyutils, autofs, Kerberos tools and pam_krb5).
const HostPackages = "lxc debootstrap cifs-utils keyutils autofs krb5-user libpam-krb5 faketime openssh-server sshpass uidmap rsync"

// Bootstrap prepares the VM: packages, the root subuid range a Proxmox host
// has, the client's name, hosts and krb5.conf, the two local users, and the
// base container the others are copied from.
func (l *Lab) Bootstrap(ctx context.Context) error {
	if _, err := l.Must(ctx, Host, "set -e; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq "+HostPackages+" >/tmp/apt-host.log 2>&1 || (tail -20 /tmp/apt-host.log; exit 1)"); err != nil {
		return err
	}
	if _, err := l.Must(ctx, Host, `set -e
grep -q '^root:100000:65536' /etc/subuid || echo root:100000:65536 >> /etc/subuid
grep -q '^root:100000:65536' /etc/subgid || echo root:100000:65536 >> /etc/subgid
hostnamectl set-hostname `+ClientFQDN+`
systemctl stop systemd-timesyncd 2>/dev/null || true
systemctl enable --now ssh >/dev/null 2>&1
systemctl restart lxc-net
install -d /srv/partage
chown 101000:101000 /srv/partage`); err != nil {
		return err
	}
	if err := l.Put(ctx, Host, "/etc/hosts", "644", "0:0", HostsFile(MITIP)); err != nil {
		return err
	}
	if err := l.Put(ctx, Host, "/etc/krb5.conf", "644", "0:0", KRB5Conf()); err != nil {
		return err
	}
	for _, u := range Users {
		// useradd -p, not chpasswd: chpasswd goes through PAM, hence through
		// pam_krb5 once it is enabled, and would try to change a Kerberos password.
		s := fmt.Sprintf("id %[1]s >/dev/null 2>&1 || useradd -m -u %[2]d -s /bin/bash -p \"$(openssl passwd -6 %[3]s)\" %[1]s", u.Name, u.UID, u.Pass)
		if _, err := l.Must(ctx, Host, s); err != nil {
			return err
		}
	}
	if err := l.Put(ctx, Host, "/etc/lxc/poc-base.conf", "644", "0:0", "lxc.include = /etc/lxc/default.conf\n"+LXCIdmap); err != nil {
		return err
	}
	_, err := l.Must(ctx, Host, `set -e
lxc-info -n base >/dev/null 2>&1 || lxc-create -n base -t download -f /etc/lxc/poc-base.conf -- -d debian -r trixie -a arm64 >/tmp/lxc-create.log 2>&1 || (tail -20 /tmp/lxc-create.log; exit 1)`)
	return err
}

// Container creates (idempotent), configures and starts a container: a copy
// of base with a static address, its name, hosts and krb5.conf. conf is
// appended to its LXC config once.
func (l *Lab) Container(ctx context.Context, name, ip, fqdn, kdcIP, conf string) error {
	root := "/var/lib/lxc/" + name + "/rootfs"
	if _, err := l.Must(ctx, Host, fmt.Sprintf("lxc-info -n %[1]s >/dev/null 2>&1 || lxc-copy -n base -N %[1]s", name)); err != nil {
		return err
	}
	if conf != "" {
		if _, err := l.Must(ctx, Host, fmt.Sprintf("grep -qF %s /var/lib/lxc/%s/config || printf '%%s' %s >> /var/lib/lxc/%s/config",
			Quote(strings.SplitN(conf, "\n", 2)[0]), name, Quote(conf), name)); err != nil {
			return err
		}
	}
	for _, f := range []struct{ path, content string }{
		{"/etc/systemd/network/eth0.network", NetworkdFile(ip)},
		{"/etc/hostname", fqdn + "\n"},
		{"/etc/hosts", HostsFile(kdcIP)},
		{"/etc/krb5.conf", KRB5Conf()},
	} {
		if err := l.Put(ctx, Host, root+f.path, "644", "100000:100000", f.content); err != nil {
			return err
		}
	}
	if _, err := l.Must(ctx, Host, fmt.Sprintf("lxc-info -n %[1]s -s | grep -q RUNNING || lxc-start -n %[1]s; lxc-wait -n %[1]s -s RUNNING -t 60", name)); err != nil {
		return err
	}
	// The network and the resolver take a few seconds to come up.
	_, err := l.Must(ctx, LXC(name), `for i in $(seq 40); do getent hosts deb.debian.org >/dev/null && exit 0; sleep 2; done; ip -br a; exit 1`)
	return err
}

// Samba creates the Samba container and its share.
func (l *Lab) Samba(ctx context.Context, kdc KDC) error {
	if err := l.Container(ctx, "samba", SambaIP, SambaFQDN, kdc.IP, "lxc.mount.entry = /srv/partage srv/partage none bind,create=dir 0 0\n"); err != nil {
		return err
	}
	n := LXC("samba")
	if _, err := l.Must(ctx, n, "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq samba smbclient krb5-user >/tmp/apt-samba.log 2>&1 || (tail -20 /tmp/apt-samba.log; exit 1)"); err != nil {
		return err
	}
	if _, err := l.Must(ctx, n, fmt.Sprintf(`set -e
id partage >/dev/null 2>&1 || useradd -M -u %d -s /usr/sbin/nologin partage`, ShareUID)); err != nil {
		return err
	}
	for _, u := range Users {
		if _, err := l.Must(ctx, n, fmt.Sprintf("id %[1]s >/dev/null 2>&1 || useradd -M -u %[2]d -s /usr/sbin/nologin %[1]s", u.Name, u.UID)); err != nil {
			return err
		}
	}
	for _, u := range append([]string{"partage"}, userNames()...) {
		if _, err := l.Must(ctx, n, fmt.Sprintf("printf '%%s\\n%%s\\n' smbpw-poc smbpw-poc | smbpasswd -a -s %s", u)); err != nil {
			return err
		}
	}
	// The share's content, owned by container uids (host side 101000, 102001...).
	_, err := l.Must(ctx, n, fmt.Sprintf(`set -e
cd /srv/partage
mkdir -p public alice-private bob-private
chown %[1]d:%[1]d . public; chmod 755 . public
echo bonjour > public/bonjour.txt; chown %[1]d:%[1]d public/bonjour.txt; chmod 644 public/bonjour.txt
echo secret-alice > alice-private/secret.txt; chown -R alice:alice alice-private; chmod 700 alice-private; chmod 600 alice-private/secret.txt
echo secret-bob > bob-private/secret.txt; chown -R bob:bob bob-private; chmod 700 bob-private; chmod 600 bob-private/secret.txt
ls -ln`, ShareUID))
	return err
}

func userNames() []string {
	var s []string
	for _, u := range Users {
		s = append(s, u.Name)
	}
	return s
}

// SambaConfigure installs smb.conf and the user map, restarts smbd, and
// returns when the port answers.
func (l *Lab) SambaConfigure(ctx context.Context, quoted bool) error {
	n := LXC("samba")
	if err := l.Put(ctx, n, "/etc/samba/smb.conf", "644", "0:0", SmbConf()); err != nil {
		return err
	}
	if err := l.Put(ctx, n, "/etc/samba/usermap", "644", "0:0", UserMap(quoted)); err != nil {
		return err
	}
	if _, err := l.Must(ctx, n, "testparm -s --suppress-prompt >/dev/null"); err != nil {
		return err
	}
	return l.RestartSmbd(ctx)
}

// RestartSmbd restarts smbd, which drops every SMB session: the client has to
// set a session up again, hence ask for a new ticket.
func (l *Lab) RestartSmbd(ctx context.Context) error {
	_, err := l.Must(ctx, LXC("samba"), `systemctl enable smbd >/dev/null 2>&1; systemctl restart smbd; for i in $(seq 20); do ss -ltn | grep -q ':445 ' && exit 0; sleep 1; done; systemctl status smbd --no-pager | tail -20; exit 1`)
	return err
}

// UseKDC points the client and Samba at kdc, regenerates the keys of every
// principal and moves the keytabs where they belong, as `pct pull` + `pct push`
// do on Proxmox.
func (l *Lab) UseKDC(ctx context.Context, kdc KDC) error {
	for _, n := range []Node{Host, LXC("samba")} {
		if err := l.Put(ctx, n, "/etc/hosts", "644", "0:0", HostsFile(kdc.IP)); err != nil {
			return err
		}
	}
	// A leftover ticket or mount of the previous KDC would mask a failure.
	if _, err := l.Sh(ctx, Host, `umount -a -t cifs 2>/dev/null; systemctl stop mnt-fstab.automount mnt-fstab.mount 2>/dev/null; rm -f /tmp/krb5cc_*; keyctl clear @u 2>/dev/null; true`); err != nil {
		return err
	}
	kn := kdc.Node()
	old := l.Tag
	l.Tag = kdc.Tag
	defer func() { l.Tag = old }()
	keytabs := []struct {
		princ, src string
		to         Node
		dst, mode  string
		owner      string
	}{
		{"cifs/" + SambaFQDN, "cifs", LXC("samba"), "/etc/samba/cifs.keytab", "600", "0:0"},
		{"root/" + ClientFQDN, "machine", Host, "/etc/krb5.keytab", "600", "0:0"},
		{"svc-partage", "svc-partage", Host, "/etc/krb5/svc-partage.keytab", "600", "0:0"},
	}
	for _, u := range Users {
		if !u.Keytab {
			continue
		}
		keytabs = append(keytabs, struct {
			princ, src string
			to         Node
			dst, mode  string
			owner      string
		}{u.Name, u.Name, Host, "/etc/krb5/" + u.Name + ".keytab", "400", fmt.Sprintf("%d:%d", u.UID, u.UID)})
	}
	for _, k := range keytabs {
		src := "/root/keytabs/" + k.src + ".keytab"
		if _, err := l.Must(ctx, kn, "mkdir -p /root/keytabs; "+kdc.KeytabScript(src, k.princ)); err != nil {
			return err
		}
		if err := l.Move(ctx, kn, k.to, src, k.dst, k.mode, k.owner); err != nil {
			return err
		}
	}
	return l.RestartSmbd(ctx)
}

// KDCLog is the KDC's log; the harness reads what was added since a mark.
func (l *Lab) KDCLog(ctx context.Context, kdc KDC) (string, error) {
	o, err := l.Sh(ctx, kdc.Node(), kdc.LogCmd())
	return o.Stdout, err
}

// SmbdLog is Samba's log.
func (l *Lab) SmbdLog(ctx context.Context) (string, error) {
	o, err := l.Sh(ctx, LXC("samba"), "cat /var/log/samba/log.smbd")
	return o.Stdout, err
}

// Wait is a pause the scenarios take (ticket expiry).
func Wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
