package automount

import (
	"fmt"
	"strings"
)

// The names of the lab. One realm, one DNS domain, three machines on the
// lxcbr0 bridge of the VM (10.0.3.0/24): the VM is the client AND the bridge's
// gateway, as a Proxmox host is.
const (
	Realm      = "POC.TEST"
	Domain     = "poc.test"
	ClientFQDN = "client.poc.test"
	ClientIP   = "10.0.3.1"
	KDCFQDN    = "kdc.poc.test"
	SambaFQDN  = "samba.poc.test"
	SambaIP    = "10.0.3.13"
	MITIP      = "10.0.3.11"
	HeimdalIP  = "10.0.3.12"
	ShareName  = "partage"

	// MachinePrincipal is what the client's keytab holds.
	MachinePrincipal = "root/" + ClientFQDN + "@" + Realm
	ServicePrincipal = "svc-partage@" + Realm
	CIFSPrincipal    = "cifs/" + SambaFQDN + "@" + Realm

	// ShareUID is the Unix user that owns the share, INSIDE the Samba container
	// (host-side 101000: the idmap offset is 100000).
	ShareUID = 1000
	// ClientUID is the local user that owns the files the mounts show.
	ClientUID = 1000
)

// Users are the two Unix users of the multiuser case: the same names and
// numbers on the client and in the Samba container.
var Users = []struct {
	Name string
	UID  int
	Pass string
}{
	{"alice", 2001, "alice-pw"},
	{"bob", 2002, "bob-pw"},
}

// HostsFile is /etc/hosts of every machine; kdcIP names the KDC in use.
func HostsFile(kdcIP string) string {
	return fmt.Sprintf(`127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
%s %s client
%s %s kdc
%s %s samba
`, ClientIP, ClientFQDN, kdcIP, KDCFQDN, SambaIP, SambaFQDN)
}

// KRB5Conf is /etc/krb5.conf of the client, the Samba container and the KDCs.
// rdns = false: the service principal is built from the name that was typed,
// never from a reverse lookup. The ccache name is per uid, so that a plain
// kinit by a user lands where cifs.upcall looks.
func KRB5Conf() string {
	return `[libdefaults]
  default_realm = POC.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  udp_preference_limit = 1
  default_ccache_name = FILE:/tmp/krb5cc_%{uid}

[realms]
  POC.TEST = {
    kdc = kdc.poc.test
    admin_server = kdc.poc.test
  }

[domain_realm]
  .poc.test = POC.TEST
  poc.test = POC.TEST
`
}

// NetworkdFile is the static address of a container (systemd-networkd).
func NetworkdFile(ip string) string {
	return fmt.Sprintf(`[Match]
Name=eth0

[Network]
Address=%s/24
Gateway=10.0.3.1
DNS=10.0.3.1
`, ip)
}

// LXCIdmap is appended to a container's config: the unprivileged mapping a
// Proxmox CT has, container uid 0 is host uid 100000.
const LXCIdmap = "lxc.idmap = u 0 100000 65536\nlxc.idmap = g 0 100000 65536\n"

// MITKDCConf is /etc/krb5kdc/kdc.conf.
func MITKDCConf() string {
	return `[kdcdefaults]
  kdc_ports = 88
  kdc_tcp_ports = 88

[realms]
  POC.TEST = {
    database_name = /var/lib/krb5kdc/principal
    key_stash_file = /etc/krb5kdc/stash
    acl_file = /etc/krb5kdc/kadm5.acl
    max_life = 10h 0m 0s
    max_renewable_life = 7d 0h 0m 0s
    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  }

[logging]
  kdc = FILE:/var/log/krb5kdc.log
  admin_server = FILE:/var/log/kadmin.log
`
}

// HeimdalKRB5Conf is /etc/krb5.conf of the Heimdal KDC container.
func HeimdalKRB5Conf() string {
	return `[libdefaults]
  default_realm = POC.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false

[realms]
  POC.TEST = {
    kdc = kdc.poc.test
    admin_server = kdc.poc.test
  }

[domain_realm]
  .poc.test = POC.TEST
  poc.test = POC.TEST

[kdc]
  database = {
    realm = POC.TEST
    dbname = sqlite:/var/lib/heimdal-kdc/heimdal.db
    mkey_file = /var/lib/heimdal-kdc/m-key
    log_file = /var/lib/heimdal-kdc/kdc.db.log
  }
  require-preauth = true
  ports = 88

[logging]
  kdc = FILE:/var/log/heimdal-kdc.log
  default = FILE:/var/log/heimdal-kdc.log
`
}

// SmbConf is smb.conf of the Samba container: a standalone server (no AD),
// Kerberos by a dedicated keytab, a username map, no guest, NTLM refused so
// that a silent fallback is impossible and not only unobserved.
func SmbConf() string {
	return `[global]
  workgroup = WORKGROUP
  netbios name = SAMBA
  server role = standalone server
  security = user
  realm = POC.TEST
  kerberos method = dedicated keytab
  dedicated keytab file = /etc/samba/cifs.keytab
  username map = /etc/samba/usermap
  map to guest = never
  ntlm auth = disabled
  server min protocol = SMB3
  disable netbios = yes
  smb ports = 445
  log level = 1 auth_audit:3 auth:3 kerberos:3
  log file = /var/log/samba/log.smbd
  max log size = 0

[partage]
  path = /srv/partage
  read only = no
  create mask = 0664
  directory mask = 0775
`
}

// UserMap is /etc/samba/usermap. quoted selects the quoted spelling of the
// principal that contains a slash.
func UserMap(quoted bool) string {
	m := "root/" + ClientFQDN + "@" + Realm
	if quoted {
		m = `"` + m + `"`
	}
	var b strings.Builder
	fmt.Fprintf(&b, "partage = %s svc-partage@%s\n", m, Realm)
	for _, u := range Users {
		fmt.Fprintf(&b, "%s = %s@%s\n", u.Name, u.Name, Realm)
	}
	return b.String()
}

// SpnegoConf is /etc/request-key.d/cifs.spnego.conf: the kernel's CIFS client
// calls cifs.upcall in the host namespace; --keytab names the machine keytab
// it falls back to when the user has no ticket. wrap is a command prefix
// (faketime for the skew case), empty otherwise.
func SpnegoConf(wrap string) string {
	if wrap != "" {
		wrap += " "
	}
	return "create  cifs.spnego    * * " + wrap + "/usr/sbin/cifs.upcall --keytab=/etc/krb5.keytab %k\n"
}

// MountOpts are the options shared by every Kerberos mount of the matrix.
func MountOpts(extra ...string) string {
	o := []string{"sec=krb5", "vers=3.1.1", "cruid=0", fmt.Sprintf("uid=%d", ClientUID), fmt.Sprintf("gid=%d", ClientUID)}
	return strings.Join(append(o, extra...), ",")
}

// FstabLine is the systemd automount line of the machine-keytab method.
func FstabLine() string {
	opts := MountOpts("username="+MachinePrincipal, "noauto", "x-systemd.automount", "x-systemd.idle-timeout=60", "_netdev")
	return fmt.Sprintf("//%s/%s /mnt/fstab cifs %s 0 0\n", SambaFQDN, ShareName, opts)
}

// AutofsMaster is /etc/auto.master.d/poc.autofs.
func AutofsMaster() string { return "/mnt/autofs /etc/auto.poc --timeout=60\n" }

// AutofsMap is /etc/auto.poc.
func AutofsMap() string {
	return fmt.Sprintf("%s -fstype=cifs,%s ://%s/%s\n", ShareName, MountOpts("username="+MachinePrincipal), SambaFQDN, ShareName)
}

// RenewService is the systemd service that fetches the service account's
// ticket from its keytab, into the ccache cifs.upcall reads for cruid=0.
func RenewService() string {
	return `[Unit]
Description=Fetch the Kerberos ticket of svc-partage from its keytab
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=KRB5CCNAME=FILE:/tmp/krb5cc_0
ExecStart=/usr/bin/kinit -k -t /etc/krb5/svc-partage.keytab svc-partage@POC.TEST
`
}

// RenewTimer fires the service at boot and then every every (a systemd time
// span): half the ticket lifetime or less.
func RenewTimer(every string) string {
	return fmt.Sprintf(`[Unit]
Description=Keep the ticket of svc-partage fresh

[Timer]
OnBootSec=10s
OnUnitActiveSec=%s
AccuracySec=1s

[Install]
WantedBy=timers.target
`, every)
}
