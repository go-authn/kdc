package automount

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Check is one yes/no assertion of a case, with what it asserts.
type Check struct {
	What string `json:"what"`
	OK   bool   `json:"ok"`
}

// Ev is one piece of evidence: a command's real output.
type Ev struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

// CaseResult is one cell of the matrix.
type CaseResult struct {
	ID     string  `json:"id"`
	KDC    string  `json:"kdc"`
	Title  string  `json:"title"`
	Pass   bool    `json:"pass"`
	Checks []Check `json:"checks"`
	Ev     []Ev    `json:"evidence"`
}

// run drives one KDC flavor through the cases.
type run struct {
	t    *testing.T
	ctx  context.Context
	l    *Lab
	k    KDC
	out  *[]CaseResult
	cur  *CaseResult
	smbd string
	kdc  string
	// since is the start of the current case on the client's clock, for journalctl.
	since string
	// kdcBase is the number of KDC log lines that predate the case: the
	// journal cannot be truncated, so the case reads what follows.
	kdcBase int
}

func (r *run) sh(n Node, script string) string {
	r.t.Helper()
	o, err := r.l.Sh(r.ctx, n, script)
	if err != nil {
		r.t.Fatal(err)
	}
	return o.String()
}

// shc is sh that also returns the exit code.
func (r *run) shc(n Node, script string) (int, string) {
	r.t.Helper()
	o, err := r.l.Sh(r.ctx, n, script)
	if err != nil {
		r.t.Fatal(err)
	}
	return o.Code, o.String()
}

func (r *run) put(n Node, path, mode, owner, content string) {
	r.t.Helper()
	if err := r.l.Put(r.ctx, n, path, mode, owner, content); err != nil {
		r.t.Fatal(err)
	}
}

func (r *run) ev(title, text string) {
	r.cur.Ev = append(r.cur.Ev, Ev{title, strings.TrimRight(text, "\n")})
}

func (r *run) check(what string, ok bool) {
	r.cur.Checks = append(r.cur.Checks, Check{what, ok})
	if !ok {
		r.t.Logf("FAIL %s/%s: %s", r.cur.KDC, r.cur.ID, what)
	}
}

// begin starts a case from a clean client: nothing mounted, no ticket, no
// unit, empty logs.
func (r *run) begin(id, title string) {
	r.t.Helper()
	r.cur = &CaseResult{ID: id, KDC: r.k.Name, Title: title}
	r.t.Logf("=== case %s/%s %s", r.k.Name, id, title)
	r.sh(Host, `systemctl stop mnt-fstab.automount mnt-fstab.mount autofs krb5-svc-partage.timer krb5-svc-partage.service 2>/dev/null
systemctl disable krb5-svc-partage.timer 2>/dev/null
umount -a -t cifs 2>/dev/null
rm -f /etc/auto.master.d/poc.autofs /etc/auto.poc /etc/systemd/system/krb5-svc-partage.service /etc/systemd/system/krb5-svc-partage.timer
grep -v ' /mnt/fstab ' /etc/fstab > /etc/fstab.new; mv /etc/fstab.new /etc/fstab
rm -f /tmp/krb5cc_*; keyctl clear @u; keyctl clear @us 2>/dev/null
chmod 600 /etc/krb5.keytab
systemctl daemon-reload
mkdir -p /mnt/direct /mnt/multi /mnt/n1 /mnt/n2 /mnt/n3a /mnt/n3b /mnt/n3c
dmesg -C 2>/dev/null; true`)
	r.put(Host, "/etc/request-key.d/cifs.spnego.conf", "644", "0:0", SpnegoConf(""))
	r.sh(LXC("samba"), ": > /var/log/samba/log.smbd")
	r.kdcMark()
	r.since = r.sh(Host, "date '+%Y-%m-%d %H:%M:%S'")
}

// end closes the case: it passes when every check holds.
func (r *run) end() {
	r.cur.Pass = len(r.cur.Checks) > 0
	for _, c := range r.cur.Checks {
		if !c.OK {
			r.cur.Pass = false
		}
	}
	*r.out = append(*r.out, *r.cur)
	r.t.Logf("=== case %s/%s pass=%v", r.k.Name, r.cur.ID, r.cur.Pass)
}

// logs reads Samba's log and the KDC's, records the interesting lines.
func (r *run) logs() {
	r.t.Helper()
	r.smbd = r.sh(LXC("samba"), "cat /var/log/samba/log.smbd")
	r.kdc = r.kdcLog()
	r.ev("smbd (authentication lines)", cutLines(keepLines(r.smbd, "AuthZ", "invalid on this", "NT_STATUS_", "principal name"), 300))
	r.ev("KDC log ("+r.k.Name+")", cutLines(shortKDC(keepLines(r.kdc, "AS_REQ", "AS-REQ", "TGS_REQ", "TGS-REQ", "ISSUE", "ERR", "SKEW", "NOT_FOUND", "not found", "skew", "Skew")), 300))
}

// kdcLog is the KDC's log since the last kdcMark.
func (r *run) kdcLog() string {
	return after(r.kdcRaw(), r.kdcBase)
}

func (r *run) kdcRaw() string {
	return strings.TrimRight(r.sh(r.k.Node(), r.k.LogCmd()), "\n")
}

// kdcMark makes the KDC log empty from here on.
func (r *run) kdcMark() {
	r.kdcBase = lineCount(r.kdcRaw())
}

func (r *run) journal() string {
	return r.sh(Host, `journalctl -t cifs.upcall --since `+Quote(r.since)+` --no-pager -o cat 2>&1 | cut -c1-240`)
}

func (r *run) mount(dir, opts, src string) (int, string) {
	r.t.Helper()
	if src == "" {
		src = SambaFQDN + "/" + ShareName
	}
	return r.shc(Host, fmt.Sprintf("mkdir -p %[1]s; mount -t cifs //%[3]s %[1]s -o %[2]s 2>&1", dir, opts, src))
}

func (r *run) findmnt(dir string) string {
	return r.sh(Host, "findmnt -t cifs -o TARGET,SOURCE,FSTYPE,OPTIONS "+Quote(dir)+" 2>&1")
}

func keepLines(s string, subs ...string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if containsAny(ln, subs...) {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}

var etypesBlob = regexp.MustCompile(`\(\d+ etypes \{[^}]*\}\) |etypes \{[^}]*\}, `)

// shortKDC drops the encryption-type lists of MIT's log lines, which push the
// client principal out of the evidence.
func shortKDC(s string) string { return etypesBlob.ReplaceAllString(s, "") }

func cutLines(s string, n int) string {
	ls := strings.Split(s, "\n")
	for i, l := range ls {
		if len(l) > n {
			ls[i] = l[:n] + "..."
		}
	}
	return strings.Join(ls, "\n")
}

// authZ reports a Kerberos authorization of the Samba user user.
func authZ(smbd, user string) bool {
	return strings.Contains(smbd, `Successful AuthZ: [SMB2,krb5] user [WORKGROUP]\[`+user+`]`)
}

// noNTLM reports that no NTLM exchange appears in the log.
func noNTLM(smbd string) bool { return !strings.Contains(smbd, "NTLMSSP]") }

// asReqs counts the AS requests of princ among the lines.
func asReqs(kdc, princ string) int {
	n := 0
	for _, ln := range strings.Split(kdc, "\n") {
		if containsAny(ln, "AS_REQ", "AS-REQ") && strings.Contains(ln, princ+"@"+Realm) {
			n++
		}
	}
	return n
}

// after is the part of the log after its first n lines.
func after(log string, n int) string {
	ls := strings.Split(log, "\n")
	if n >= len(ls) {
		return ""
	}
	return strings.Join(ls[n:], "\n")
}

func lineCount(s string) int { return len(strings.Split(s, "\n")) }

const share = "/mnt/direct"

func (r *run) caseUsermap() {
	r.begin("U", "Samba username map: does a principal with a slash match, quoted or not")
	opts := MountOpts("username=" + MachinePrincipal)
	for _, v := range []struct {
		name, line string
		want       bool
	}{
		{"plain, WORKGROUP\\ key", `partage = WORKGROUP\root/` + ClientFQDN, true},
		{"quoted, WORKGROUP\\ key", `partage = "WORKGROUP\root/` + ClientFQDN + `"`, true},
		{"plain, no workgroup", `partage = root/` + ClientFQDN, false},
		{"quoted, no workgroup", `partage = "root/` + ClientFQDN + `"`, false},
		{"with the realm", `partage = root/` + ClientFQDN + `@` + Realm, false},
	} {
		r.put(LXC("samba"), "/etc/samba/usermap", "644", "0:0", v.line+"\n")
		r.sh(Host, "umount "+share+" 2>/dev/null; keyctl clear @u; rm -f /tmp/krb5cc_0")
		r.sh(LXC("samba"), ": > /var/log/samba/log.smbd")
		code, out := r.mount(share, opts, "")
		smbd := r.sh(LXC("samba"), "cat /var/log/samba/log.smbd")
		r.ev("usermap "+v.name+": "+v.line, fmt.Sprintf("mount rc=%d %s\n%s", code, out,
			cutLines(keepLines(smbd, "AuthZ", "invalid on this", "principal name"), 220)))
		if v.want {
			r.check(v.name+": mounted, Samba user partage", code == 0 && authZ(smbd, "partage"))
		} else {
			r.check(v.name+": refused (error 13), name invalid on this system",
				code != 0 && strings.Contains(out, "(13)") && strings.Contains(smbd, "is invalid on this system"))
		}
	}
	r.put(LXC("samba"), "/etc/samba/usermap", "644", "0:0", UserMap(false))
	r.end()
}

func (r *run) caseFstab() {
	r.begin("A1", "machine keytab, /etc/fstab line with x-systemd.automount")
	line := FstabLine()
	if _, err := r.l.sh(r.ctx, Host, []byte(line), "cat >> /etc/fstab"); err != nil {
		r.t.Fatal(err)
	}
	r.l.Rec.Add(RecFile{Tag: r.l.Tag, Node: Host, Path: "/etc/fstab (line added)", Mode: "644", Owner: "0:0", Content: line})
	r.sh(Host, "systemctl daemon-reload; systemctl restart mnt-fstab.automount")
	r.ev("before any access", r.sh(Host, "systemctl is-active mnt-fstab.automount; findmnt -o TARGET,FSTYPE /mnt/fstab"))
	code, ls := r.shc(Host, "ls /mnt/fstab; echo")
	fm := r.findmnt("/mnt/fstab")
	r.ev("ls /mnt/fstab (the access that triggers the mount)", ls)
	r.ev("findmnt", fm)
	r.ev("klist (no ticket cache, nobody ran kinit)", r.sh(Host, "klist 2>&1; echo ---; klist -k /etc/krb5.keytab"))
	r.ev("cifs.upcall (journal)", r.journal())
	r.logs()
	r.check("the share is listed through the automount", code == 0 && strings.Contains(ls, "public"))
	r.check("findmnt: fstype cifs with sec=krb5", strings.Contains(fm, "cifs") && strings.Contains(fm, "sec=krb5"))
	r.check("smbd: Successful AuthZ [SMB2,krb5] as partage", authZ(r.smbd, "partage"))
	r.check("smbd: no NTLM", noNTLM(r.smbd))
	r.check("KDC: AS request for "+MachinePrincipal, asReqs(r.kdc, "root/"+ClientFQDN) > 0)
	r.end()
}

func (r *run) caseAutofs() {
	r.begin("A2", "machine keytab, autofs")
	r.put(Host, "/etc/auto.master.d/poc.autofs", "644", "0:0", AutofsMaster())
	r.put(Host, "/etc/auto.poc", "644", "0:0", AutofsMap())
	r.sh(Host, "systemctl restart autofs; sleep 1")
	code, ls := r.shc(Host, "ls /mnt/autofs/partage; echo")
	fm := r.findmnt("/mnt/autofs/partage")
	r.ev("ls /mnt/autofs/partage", ls)
	r.ev("findmnt", fm)
	r.ev("klist", r.sh(Host, "klist 2>&1"))
	r.logs()
	r.check("the share is listed through autofs", code == 0 && strings.Contains(ls, "public"))
	r.check("findmnt: fstype cifs with sec=krb5", strings.Contains(fm, "cifs") && strings.Contains(fm, "sec=krb5"))
	r.check("smbd: Successful AuthZ [SMB2,krb5] as partage", authZ(r.smbd, "partage"))
	r.check("smbd: no NTLM", noNTLM(r.smbd))
	r.check("KDC: AS request for "+MachinePrincipal, asReqs(r.kdc, "root/"+ClientFQDN) > 0)
	r.end()
}

func (r *run) casePitfall() {
	r.begin("A3", "machine keytab, but no username= option: which principal does cifs.upcall try")
	code, out := r.mount(share, MountOpts(), "")
	r.ev("mount without username=", fmt.Sprintf("rc=%d\n%s", code, out))
	r.ev("cifs.upcall (journal)", r.journal())
	r.logs()
	r.check("the mount is refused", code != 0)
	jr := r.journal()
	r.check("cifs.upcall tried user=root and found no key for it in the keytab",
		strings.Contains(jr, "user=root;") && strings.Contains(jr, "krb5_get_init_creds_keytab"))
	r.check("the KDC was asked for root@"+Realm+" (the login name), not for the machine principal",
		asReqs(r.kdc, "root") > 0 && asReqs(r.kdc, "root/"+ClientFQDN) == 0)
	r.check("smbd: no authorization at all", !strings.Contains(r.smbd, "Successful AuthZ"))
	r.end()
}

func (r *run) installRenew(every string) {
	r.put(Host, "/etc/systemd/system/krb5-svc-partage.service", "644", "0:0", RenewService())
	r.put(Host, "/etc/systemd/system/krb5-svc-partage.timer", "644", "0:0", RenewTimer(every))
	r.sh(Host, "systemctl daemon-reload; systemctl enable --now krb5-svc-partage.timer; systemctl start krb5-svc-partage.service")
}

func (r *run) caseService() {
	r.begin("B", "service account svc-partage, ticket kept by a systemd service and timer")
	r.installRenew("30min")
	r.ev("timer", r.sh(Host, "systemctl list-timers krb5-svc-partage.timer --no-pager 2>&1"))
	r.ev("klist of /tmp/krb5cc_0", r.sh(Host, "KRB5CCNAME=FILE:/tmp/krb5cc_0 klist 2>&1"))
	code, out := r.mount(share, MountOpts(), "")
	fm := r.findmnt(share)
	ls := r.sh(Host, "ls "+share)
	r.ev("mount (no username=)", fmt.Sprintf("rc=%d %s", code, out))
	r.ev("findmnt", fm)
	r.ev("ls", ls)
	r.logs()
	r.check("mounted without any human kinit", code == 0 && strings.Contains(ls, "public"))
	r.check("findmnt: sec=krb5", strings.Contains(fm, "sec=krb5"))
	r.check("smbd: Successful AuthZ [SMB2,krb5] as partage (map of svc-partage)", authZ(r.smbd, "partage"))
	r.check("smbd: no NTLM", noNTLM(r.smbd))
	r.check("KDC: AS request for svc-partage", asReqs(r.kdc, "svc-partage") > 0)
	r.end()
}

func (r *run) caseMultiuser() {
	r.begin("C", "multiuser,sec=krb5: alice (per-user keytab), bob (pam_krb5 over ssh), nobody")
	// With multiuser the kernel authenticates every uid on its own, root
	// included, and cifs.upcall reads the keytab only for the mount's username=:
	// root needs its own ticket, here from the machine keytab.
	r.ev("root: kinit -k -t (the machine's own ticket)", r.sh(Host, "kinit -k -t /etc/krb5.keytab "+MachinePrincipal+" && klist 2>&1"))
	code, out := r.mount("/mnt/multi", MountOpts("multiuser", "noperm", "username="+MachinePrincipal), "")
	fm := r.findmnt("/mnt/multi")
	r.ev("mount", fmt.Sprintf("rc=%d %s", code, out))
	r.ev("findmnt", fm)
	r.check("superblock mounted with multiuser and sec=krb5", code == 0 && strings.Contains(fm, "multiuser") && strings.Contains(fm, "sec=krb5"))
	// alice: a ticket from her own keytab.
	r.ev("alice: kinit -k -t (no password)", r.sh(User("alice"), "kinit -k -t /etc/krb5/alice.keytab alice@"+Realm+" && klist 2>&1"))
	ac, aout := r.shc(User("alice"), "id -u; cat /mnt/multi/alice-private/secret.txt; cat /mnt/multi/bob-private/secret.txt 2>&1")
	r.ev("alice reads her file, then bob's", fmt.Sprintf("rc=%d\n%s", ac, aout))
	// bob: pam_krb5 at an ssh login, the ticket lives in the session.
	bc, bout := r.shc(Host, `sshpass -p bob-pw ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password,keyboard-interactive bob@localhost 'id -u; echo KRB5CCNAME=$KRB5CCNAME; klist 2>&1; cat /mnt/multi/bob-private/secret.txt; cat /mnt/multi/alice-private/secret.txt 2>&1' 2>&1`)
	r.ev("bob: ssh login (pam_krb5), reads his file, then alice's", fmt.Sprintf("rc=%d\n%s", bc, bout))
	nc, nout := r.shc(User("nobody"), "id -u; cat /mnt/multi/public/bonjour.txt 2>&1")
	r.ev("nobody: no ticket", fmt.Sprintf("rc=%d\n%s", nc, nout))
	rc, rout := r.shc(Host, "cat /mnt/multi/alice-private/secret.txt 2>&1")
	r.ev("root (machine identity partage) reads alice's file", fmt.Sprintf("rc=%d\n%s", rc, rout))
	r.ev("cifs.upcall (journal)", r.journal())
	r.logs()
	r.check("alice (uid 2001) reads secret-alice", strings.Contains(aout, "secret-alice"))
	r.check("alice is refused bob's file", !strings.Contains(aout, "secret-bob") && strings.Contains(aout, "Permission denied"))
	r.check("bob got a ticket from pam_krb5 (klist in the session)", strings.Contains(bout, "bob@"+Realm))
	r.check("bob (uid 2002) reads secret-bob", strings.Contains(bout, "secret-bob"))
	r.check("bob is refused alice's file", !strings.Contains(bout, "secret-alice") && strings.Contains(bout, "Permission denied"))
	r.check("a user with no ticket reads nothing", nc != 0 && strings.HasPrefix(nout, "65534\ncat: "))
	r.check("root sees the share as partage and is refused alice-private", rc != 0 && strings.Contains(rout, "Permission denied"))
	r.check("smbd: Successful AuthZ [SMB2,krb5] for alice, bob and partage",
		authZ(r.smbd, "alice") && authZ(r.smbd, "bob") && authZ(r.smbd, "partage"))
	r.check("smbd: no NTLM", noNTLM(r.smbd))
	r.end()
}

func (r *run) caseIP() {
	r.begin("N1", "negative: mount by IP address, no NTLM fallback")
	conf := strings.Replace(SmbConf(), "ntlm auth = disabled", "ntlm auth = ntlmv2-only", 1)
	r.put(LXC("samba"), "/etc/samba/smb.conf", "644", "0:0", conf)
	if err := r.l.RestartSmbd(r.ctx); err != nil {
		r.t.Fatal(err)
	}
	r.sh(LXC("samba"), ": > /var/log/samba/log.smbd")
	r.kdcMark()
	code, out := r.mount("/mnt/n1", MountOpts("username="+MachinePrincipal), SambaIP+"/"+ShareName)
	r.ev("sec=krb5 by IP (the server ACCEPTS NTLMv2 for this test)", fmt.Sprintf("rc=%d\n%s", code, out))
	r.ev("cifs.upcall (journal)", r.journal())
	r.logs()
	smbdKrb, kdcKrb := r.smbd, r.kdc
	r.check("sec=krb5 by IP is refused", code != 0)
	r.check("the KDC does not know cifs/"+SambaIP, containsAny(kdcKrb, "SERVER_NOT_FOUND", "not found in Kerberos database", "Server not found", "UNKNOWN_SERVER", "Server unknown", "LOOKING_UP_SERVER"))
	r.check("smbd: no authorization and no NTLM exchange", !strings.Contains(smbdKrb, "Successful AuthZ") && noNTLM(smbdKrb))
	r.sh(LXC("samba"), ": > /var/log/samba/log.smbd")
	code2, out2 := r.mount("/mnt/n1", "vers=3.1.1,sec=ntlmssp,username=partage,password=smbpw-poc", SambaIP+"/"+ShareName)
	smbd2 := r.sh(LXC("samba"), "cat /var/log/samba/log.smbd")
	r.ev("control: sec=ntlmssp by IP with a password (proves the server WOULD accept NTLM)", fmt.Sprintf("rc=%d %s\n%s", code2, out2, cutLines(keepLines(smbd2, "AuthZ"), 220)))
	r.check("control: the same server accepts NTLMSSP when the client asks for it", code2 == 0 && strings.Contains(smbd2, "Successful AuthZ: [SMB2,NTLMSSP]"))
	r.sh(Host, "umount /mnt/n1 2>/dev/null")
	if err := r.l.SambaConfigure(r.ctx, false); err != nil {
		r.t.Fatal(err)
	}
	r.end()
}

// NoSyncConf is a krb5.conf with kdc_timesync off, for the skew case.
const NoSyncConf = "/etc/krb5-nosync.conf"

func (r *run) caseSkew() {
	r.begin("N2", "negative: client clock ahead of the KDC (limit 5 minutes)")
	opts := MountOpts("username=" + MachinePrincipal)
	r.put(Host, "/etc/request-key.d/cifs.spnego.conf", "644", "0:0", SpnegoConf("/usr/bin/faketime -f +4m"))
	code4, out4 := r.mount(share, opts, "")
	r.ev("+4 minutes (inside the tolerance)", fmt.Sprintf("rc=%d %s", code4, out4))
	reset := "umount " + share + " 2>/dev/null; keyctl clear @u; rm -f /tmp/krb5cc_0"
	r.sh(Host, reset)
	// libkrb5 keeps a time offset learned from the KDC's error reply
	// (kdc_timesync, on by default): a client ahead by 10 minutes is corrected
	// and succeeds. The refusal needs the option off.
	r.put(Host, "/etc/request-key.d/cifs.spnego.conf", "644", "0:0", SpnegoConf("/usr/bin/faketime -f +10m"))
	code10, out10 := r.mount(share, opts, "")
	r.ev("+10 minutes, krb5.conf as installed (kdc_timesync on by default)", fmt.Sprintf("rc=%d %s", code10, out10))
	r.sh(Host, reset)
	r.sh(LXC("samba"), ": > /var/log/samba/log.smbd")
	r.kdcMark()
	r.since = r.sh(Host, "date '+%Y-%m-%d %H:%M:%S'")
	r.put(Host, NoSyncConf, "644", "0:0", strings.Replace(KRB5Conf(), "rdns = false", "rdns = false\n  kdc_timesync = 0", 1))
	r.put(Host, "/etc/request-key.d/cifs.spnego.conf", "644", "0:0", SpnegoConf("/usr/bin/faketime -f +10m /usr/bin/env KRB5_CONFIG="+NoSyncConf))
	codeNS, outNS := r.mount(share, opts, "")
	r.ev("+10 minutes, kdc_timesync = 0 (outside the tolerance)", fmt.Sprintf("rc=%d %s", codeNS, outNS))
	jr := r.journal()
	r.ev("cifs.upcall (journal)", jr)
	r.logs()
	r.check("+4 minutes: mounted", code4 == 0)
	r.check("+10 minutes, default krb5.conf: mounted anyway (libkrb5 resynchronises on the KDC's time)", code10 == 0)
	r.check("+10 minutes, kdc_timesync = 0: refused", codeNS != 0)
	// -1765328236 is KRB5_KDCREP_SKEW, "Clock skew too great in KDC reply"
	// (kinit prints that text for the same run, see the guide).
	r.check("the refusal is a clock skew (cifs.upcall: krb5_get_init_creds_keytab -1765328236 = KRB5_KDCREP_SKEW)",
		strings.Contains(strings.ToLower(r.kdc+jr), "skew") || strings.Contains(jr, "krb5_get_init_creds_keytab: -1765328236"))
	r.ev("same clock, kinit: the text of that code", r.sh(Host, "faketime -f +10m env KRB5_CONFIG="+NoSyncConf+" kinit -k -t /etc/krb5.keytab "+MachinePrincipal+" 2>&1"))
	r.check("smbd: no authorization, no NTLM", !strings.Contains(r.smbd, "Successful AuthZ") && noNTLM(r.smbd))
	r.put(Host, "/etc/request-key.d/cifs.spnego.conf", "644", "0:0", SpnegoConf(""))
	r.end()
}

func (r *run) caseKeytabMode() {
	r.begin("N4", "negative: keytab with mode 0644")
	opts := MountOpts("username=" + MachinePrincipal)
	r.sh(Host, "chmod 644 /etc/krb5.keytab")
	r.ev("stat", r.sh(Host, "stat -c '%a %U:%G %n' /etc/krb5.keytab"))
	code, out := r.mount(share, opts, "")
	r.ev("mount with the 0644 keytab", fmt.Sprintf("rc=%d %s", code, out))
	steal := r.sh(User("alice"), "kinit -k -t /etc/krb5.keytab root/"+ClientFQDN+"@"+Realm+" 2>&1; klist 2>&1; kdestroy 2>&1")
	r.ev("0644: alice (uid 2001) runs kinit -k -t /etc/krb5.keytab", steal)
	r.sh(Host, "chmod 600 /etc/krb5.keytab")
	r.ev("stat", r.sh(Host, "stat -c '%a %U:%G %n' /etc/krb5.keytab"))
	c600, out600 := r.shc(User("alice"), "kinit -k -t /etc/krb5.keytab root/"+ClientFQDN+"@"+Realm+" 2>&1")
	r.ev("0600: the same command", fmt.Sprintf("rc=%d %s", c600, out600))
	r.logs()
	r.check("Kerberos does not check the mode: the mount works with 0644", code == 0 && authZ(r.smbd, "partage"))
	r.check("0644: any local user gets the machine's ticket", strings.Contains(steal, "root/"+ClientFQDN+"@"+Realm))
	r.check("0600: the same user is refused", c600 != 0 && containsAny(out600, "Permission denied", "Key table file", "cannot be read"))
	r.end()
}

// lifetimeNames are the principals whose tickets live 3 minutes.
func lifetimeNames() []string {
	return []string{"krbtgt/" + Realm, "root/" + ClientFQDN, "svc-partage", "alice", "cifs/" + SambaFQDN}
}

func (r *run) setLife(life string) {
	for _, n := range lifetimeNames() {
		r.sh(r.k.Node(), r.k.MaxLifeScript(n, life))
	}
}

func (r *run) caseLifetime() {
	r.begin("N3", "ticket lifetime of 3 minutes: re-acquisition at reconnect")
	r.setLife("3 minutes")
	defer r.setLife("10 hours")
	r.installRenew("1min")
	r.sh(Host, "sleep 1; rm -f /tmp/krb5cc_2001")
	r.sh(User("alice"), "kinit -k -t /etc/krb5/alice.keytab alice@"+Realm)
	for _, m := range []struct{ dir, opts string }{
		{"/mnt/n3a", MountOpts("username=" + MachinePrincipal)},
		{"/mnt/n3b", MountOpts()},
		{"/mnt/n3c", "sec=krb5,vers=3.1.1,cruid=2001,uid=2001,gid=2001"},
	} {
		code, out := r.mount(m.dir, m.opts, "")
		r.check("mounted "+m.dir, code == 0)
		if code != 0 {
			r.ev("mount "+m.dir, out)
		}
	}
	r.ev("t0: ccache of the service account (3 minute ticket)", r.sh(Host, "KRB5CCNAME=FILE:/tmp/krb5cc_0 klist 2>&1"))
	r.ev("t0: ccache of alice, no timer", r.sh(User("alice"), "klist 2>&1"))
	if err := Wait(r.ctx, 200*time.Second); err != nil {
		r.t.Fatal(err)
	}
	mark := lineCount(r.kdcLog())
	r.ev("t0+200s: ccache of the service account (the timer renewed it)", r.sh(Host, "KRB5CCNAME=FILE:/tmp/krb5cc_0 klist 2>&1"))
	r.ev("t0+200s: ccache of alice (expired, nobody renews it)", r.sh(User("alice"), "klist 2>&1"))
	r.sh(LXC("samba"), "systemctl restart smbd; sleep 3")
	try := func(dir string) (bool, string) {
		code, out := r.shc(Host, fmt.Sprintf("for i in $(seq 25); do if ls %s >/dev/null 2>&1; then echo reconnected after ${i}s; exit 0; fi; sleep 1; done; ls %s 2>&1; exit 1", dir, dir))
		return code == 0, out
	}
	okA, outA := try("/mnt/n3a")
	okB, outB := try("/mnt/n3b")
	okC, outC := try("/mnt/n3c")
	r.ev("smbd restarted: /mnt/n3a, machine keytab", outA)
	r.ev("smbd restarted: /mnt/n3b, service account with timer", outB)
	r.ev("smbd restarted: /mnt/n3c, alice, no timer (control)", outC)
	r.ev("cifs.upcall (journal)", r.journal())
	r.logs()
	later := after(r.kdc, mark)
	r.ev("KDC log after the 200 s mark", cutLines(shortKDC(keepLines(later, "AS_REQ", "AS-REQ", "TGS_REQ", "TGS-REQ")), 300))
	// Measured: the reconnect of /mnt/n3a shows no AS request for root/<fqdn>; the
	// kernel reconnects with the credentials of the session it shares with /mnt/n3b
	// (same server, same cruid), and the upcall that does reach the KDC asks for
	// root@REALM, which does not exist. So only survival is asserted here.
	r.check("machine keytab: the mount survives the expiry", okA)
	r.check("service account: the mount survives the expiry thanks to the timer", okB && asReqs(r.kdc, "svc-partage") >= 3)
	r.check("control, no timer: reconnect fails with the expired ticket", !okC)
	r.end()
}

func TestMatrix(t *testing.T) {
	l, ctx := e2eLab(t)
	var results []CaseResult
	for _, k := range []KDC{MIT(), Heimdal()} {
		if os.Getenv("AUTOMOUNT_KDC") != "" && os.Getenv("AUTOMOUNT_KDC") != k.Name {
			continue
		}
		l.Tag = k.Tag
		if err := l.UseKDC(ctx, k); err != nil {
			t.Fatal(err)
		}
		if err := l.SambaConfigure(ctx, false); err != nil {
			t.Fatal(err)
		}
		r := &run{t: t, ctx: ctx, l: l, k: k, out: &results}
		for _, c := range []struct {
			id string
			fn func()
		}{{"U", r.caseUsermap}, {"A1", r.caseFstab}, {"A2", r.caseAutofs}, {"A3", r.casePitfall}, {"B", r.caseService},
			{"C", r.caseMultiuser}, {"N1", r.caseIP}, {"N2", r.caseSkew}, {"N4", r.caseKeytabMode}, {"N3", r.caseLifetime}} {
			if only := os.Getenv("AUTOMOUNT_CASE"); only != "" && only != c.id {
				continue
			}
			c.fn()
		}
	}
	dir := outDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "matrix.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.Rec.Save(filepath.Join(dir, "files")); err != nil {
		t.Fatal(err)
	}
	for _, c := range results {
		if !c.Pass {
			t.Errorf("%s/%s FAILED", c.KDC, c.ID)
		}
	}
}
