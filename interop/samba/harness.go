// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// Fixed names of the experiment. The host name resolves to the Samba VM
// itself (/etc/hosts), so smbclient runs where smbd runs.
const (
	Host  = "smbhost.interop.test"
	User  = "alice"
	Share = "share"
	// Pass is a throwaway password of a throwaway principal in a throwaway VM.
	Pass = "Interop-pw-1"
)

// Env is what a KDC case hands to the Samba side.
type Env struct {
	Realm   string
	KDC     string // host:port as krb5.conf wants it
	Keytab  []byte // cifs/Host@Realm, in MIT keytab format
	KDCNote string // which KDC, which version
}

// Relaxation is one Samba-side setting, applied on top of the baseline.
type Relaxation struct {
	Name string
	Role string // "server role" replacing the baseline's standalone server
	Line string // an extra smb.conf [global] line; empty for the baseline
}

// Result is one cell row of the matrix.
type Result struct {
	KDC        string
	KDCVersion string
	Relaxation string
	TGT        bool
	TicketEnc  string
	ADTypes    []string
	PAC        bool
	SmbOK      bool
	SmbCode    int
	SmbOutput  string
	Evidence   []string
	Err        string

	// Ccache and Keytab are the evidence the PAC verdict was decoded from; the
	// matrix test saves them as fixtures. Not part of matrix.json.
	Ccache, Keytab []byte `json:"-"`
}

// pause is the wait between two probes of a starting smbd; tests set it to 0.
var pause = 200 * time.Millisecond

// Samba is the file server under test: a container, so that every run starts
// from a clean one.
type Samba struct{ VM Node }

// StartSamba creates the Samba container, named Host on the network.
func StartSamba(ctx context.Context) (Samba, error) {
	n, err := StartNode(ctx, "interop-samba", "samba", Host)
	return Samba{VM: n}, err
}

const logPath = "/var/log/samba/log.smbd"

func (s Samba) smbConf(realm string, rx Relaxation) string {
	var b strings.Builder
	b.WriteString("[global]\n")
	b.WriteString("  workgroup = WORKGROUP\n  netbios name = SMBHOST\n")
	role := "standalone server"
	if rx.Role != "" {
		role = rx.Role
	}
	b.WriteString("  server role = " + role + "\n")
	if rx.Role == "" {
		b.WriteString("  security = user\n")
	}
	fmt.Fprintf(&b, "  realm = %s\n", realm)
	b.WriteString("  kerberos method = dedicated keytab\n  dedicated keytab file = /etc/samba/cifs.keytab\n")
	b.WriteString("  username map = /etc/samba/usermap\n  map to guest = never\n")
	b.WriteString("  log level = 10\n  log file = " + logPath + "\n  max log size = 0\n")
	b.WriteString("  disable netbios = yes\n  smb ports = 445\n")
	if rx.Line != "" {
		b.WriteString("  " + rx.Line + "\n")
	}
	fmt.Fprintf(&b, "\n[%s]\n  path = /srv/%s\n  read only = yes\n", Share, Share)
	return b.String()
}

func krb5Conf(realm, kdc string) string {
	return fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  udp_preference_limit = 1
  default_ccache_name = FILE:/tmp/krb5cc_interop

[realms]
  %s = {
    kdc = %s
  }

[domain_realm]
  %s = %s
  .interop.test = %s
`, realm, realm, kdc, Host, realm, realm)
}

// Prepare installs krb5.conf, the host name, the user, the share, the keytab
// and the user map on the Samba VM. It does not start the KDC.
func (s Samba) Prepare(ctx context.Context, e Env) error {
	v := s.VM
	if err := v.WriteFile(ctx, "/etc/krb5.conf", "644", []byte(krb5Conf(e.Realm, e.KDC))); err != nil {
		return err
	}
	if o, err := v.Sudo(ctx, nil, "id", User); err != nil {
		return err
	} else if o.Code != 0 {
		if _, err := v.Must(ctx, nil, "useradd", "-m", User); err != nil {
			return err
		}
	}
	if _, err := v.Must(ctx, []byte(Pass+"\n"+Pass+"\n"), "smbpasswd", "-a", "-s", User); err != nil {
		return err
	}
	if _, err := v.Must(ctx, nil, "mkdir", "-p", "/srv/"+Share); err != nil {
		return err
	}
	if _, err := v.Must(ctx, nil, "chmod", "755", "/srv/"+Share); err != nil {
		return err
	}
	if err := v.WriteFile(ctx, "/srv/"+Share+"/hello.txt", "644", []byte("hello\n")); err != nil {
		return err
	}
	if err := v.WriteFile(ctx, "/etc/samba/usermap", "644", []byte(User+" = "+User+"@"+e.Realm+"\n")); err != nil {
		return err
	}
	return v.WriteFile(ctx, "/etc/samba/cifs.keytab", "600", e.Keytab)
}

// Run configures smbd with the relaxation, fetches a TGT and a service ticket
// as User, decodes the ticket, and lists the share with Kerberos required.
func (s Samba) Run(ctx context.Context, e Env, kdcName, kdcVersion string, rx Relaxation) Result {
	r := Result{KDC: kdcName, KDCVersion: kdcVersion, Relaxation: rx.Name}
	fail := func(err error) Result { r.Err = err.Error(); return r }
	v := s.VM
	if err := v.WriteFile(ctx, "/etc/samba/smb.conf", "644", []byte(s.smbConf(e.Realm, rx))); err != nil {
		return fail(err)
	}
	if o, err := v.Sudo(ctx, nil, "testparm", "-s", "--suppress-prompt"); err != nil || o.Code != 0 {
		return fail(fmt.Errorf("testparm: %v %s", err, o))
	}
	if _, err := v.Must(ctx, nil, "mkdir", "-p", "/var/log/samba"); err != nil {
		return fail(err)
	}
	if err := v.Spawn(ctx, "smbd", "--foreground", "--no-process-group"); err != nil {
		return fail(err)
	}
	up := false
	for i := 0; i < 50 && !up; i++ {
		o, _ := v.Run(ctx, nil, "smbcontrol", "smbd", "ping")
		if up = o.Code == 0; !up {
			time.Sleep(pause)
		}
	}
	if !up {
		return fail(fmt.Errorf("smbd did not come up"))
	}

	_, _ = v.Run(ctx, nil, "kdestroy")
	if o, err := v.Run(ctx, []byte(Pass+"\n"), "kinit", User+"@"+e.Realm); err != nil || o.Code != 0 {
		return fail(fmt.Errorf("kinit: %v %s", err, o))
	}
	r.TGT = true
	if o, err := v.Run(ctx, nil, "kvno", "cifs/"+Host); err != nil || o.Code != 0 {
		return fail(fmt.Errorf("kvno: %v %s", err, o))
	}
	if o, err := v.Run(ctx, nil, "klist", "-e"); err == nil {
		r.TicketEnc = lastCifsEnc(o.String())
	}
	cc, err := v.ReadFile(ctx, "/tmp/krb5cc_interop")
	if err != nil {
		return fail(err)
	}
	r.Ccache, r.Keytab = cc, e.Keytab
	var kt keytab.Keytab
	if err := kt.Unmarshal(e.Keytab); err != nil {
		return fail(fmt.Errorf("the service keytab does not decode: %w", err))
	}
	r.ADTypes, r.PAC, err = TicketTypes(cc, &kt, "cifs/"+Host)
	if err != nil {
		return fail(err)
	}

	o, err := v.Run(ctx, nil, "smbclient", "--use-kerberos=required", "//"+Host+"/"+Share, "--command=ls")
	if err != nil {
		return fail(err)
	}
	r.SmbCode, r.SmbOutput = o.Code, o.String()
	r.SmbOK = o.Code == 0 && strings.Contains(o.String(), "hello.txt")
	if lg, err := v.ReadFile(ctx, logPath); err == nil {
		r.Evidence = Evidence(string(lg))
	}
	return r
}

// FullLog returns smbd's level-10 log of the last Run.
func (s Samba) FullLog(ctx context.Context) string {
	b, _ := s.VM.ReadFile(ctx, logPath)
	return string(b)
}

// evidenceMarks select, from a level-10 log, the lines that say how the
// ticket was judged. Level 10 is far too long to read; these are the places
// where the PAC and the user lookup are decided.
var evidenceMarks = []string{
	"obtaining PAC", "Unable to find PAC", "resorting to local user lookup", "failing to allow access",
	"Kerberos ticket principal name", "make_session_info_krb5", "found user alice in passdb",
	"Successful AuthZ", "NT_STATUS_NO_IMPERSONATION_TOKEN", "NT_STATUS_LOGON_FAILURE", "NT_STATUS_NO_SUCH_USER",
	"gss_accept_sec_context failed", "Failed to find PAC",
}

// Evidence picks the decisive lines out of a log, at most 40.
func Evidence(log string) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		for _, m := range evidenceMarks {
			if strings.Contains(l, m) {
				out = append(out, strings.TrimSpace(l))
				break
			}
		}
		if len(out) == 40 {
			break
		}
	}
	return out
}

// lastCifsEnc extracts the encryption line that follows the cifs entry of a
// `klist -e` listing.
func lastCifsEnc(klist string) string {
	lines := strings.Split(klist, "\n")
	for i, l := range lines {
		if strings.Contains(l, "cifs/") && i+1 < len(lines) {
			return strings.TrimSpace(lines[i+1])
		}
	}
	return ""
}
