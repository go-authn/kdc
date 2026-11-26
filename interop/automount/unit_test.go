package automount

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// call is one script the fake saw.
type call struct {
	Node   Node
	Stdin  string
	Script string
}

// fake is an Exec that records every call. failAt >= 0 makes that call fail,
// with a transport error (asErr) or a non-zero exit; reply answers the others.
type fake struct {
	calls  []call
	failAt int
	asErr  bool
	reply  func(c call) Out
}

func newFake() *fake { return &fake{failAt: -1} }

func (f *fake) Run(_ context.Context, n Node, stdin []byte, script string) (Out, error) {
	c := call{n, string(stdin), script}
	i := len(f.calls)
	f.calls = append(f.calls, c)
	if i == f.failAt {
		if f.asErr {
			return Out{}, errors.New("transport down")
		}
		return Out{Code: 1, Stderr: "boom"}, nil
	}
	if f.reply != nil {
		return f.reply(c), nil
	}
	return Out{}, nil
}

// everyStepFails runs fn once to count its steps, then once per step with
// that step failing (both ways), and demands an error each time: a step whose
// failure is swallowed would let the matrix report a lab that never existed.
func everyStepFails(t *testing.T, fn func(l *Lab) error) {
	t.Helper()
	base := newFake()
	if err := fn(NewLab(base, nil)); err != nil {
		t.Fatalf("all steps ok: %v", err)
	}
	n := len(base.calls)
	if n == 0 {
		t.Fatal("no step ran")
	}
	for i := 0; i < n; i++ {
		for _, asErr := range []bool{false, true} {
			f := newFake()
			f.failAt, f.asErr = i, asErr
			if err := fn(NewLab(f, nil)); err == nil {
				t.Errorf("step %d/%d (%q on %s, asErr=%v) failed and fn returned nil", i, n, firstLine(base.calls[i].Script), base.calls[i].Node, asErr)
			}
		}
	}
}

func firstLine(s string) string { return strings.SplitN(strings.TrimSpace(s), "\n", 2)[0] }

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":          `''`,
		"a b":       `'a b'`,
		"it's":      `'it'\''s'`,
		"$HOME `x`": "'$HOME `x`'",
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestWrap(t *testing.T) {
	if s, err := Wrap(Host, "id"); err != nil || s != "id" {
		t.Errorf("host: %q %v", s, err)
	}
	s, err := Wrap(LXC("samba"), "echo 'x'")
	if err != nil || !strings.HasPrefix(s, "lxc-attach -n 'samba' --clear-env -- bash -c ") || !strings.Contains(s, `'echo '\''x'\'''`) {
		t.Errorf("lxc: %q %v", s, err)
	}
	s, err = Wrap(User("alice"), "id")
	if err != nil || s != "runuser -u 'alice' -- bash -c 'id'" {
		t.Errorf("user: %q %v", s, err)
	}
	if _, err := Wrap(Node("vm:x"), "id"); err == nil {
		t.Error("unknown node accepted")
	}
}

func TestOutString(t *testing.T) {
	if got := (Out{Stdout: "a\n", Stderr: "b\n\n"}).String(); got != "a\nb" {
		t.Errorf("got %q", got)
	}
}

// TestMain lets the test binary play `tart` (a copy of it is put on PATH by
// fakeTart): it echoes its arguments and its stdin, and exits with the code in
// $FAKE_RC. A Go fake runs on every platform, a shell script does not.
func TestMain(m *testing.M) {
	if os.Getenv("AUTOMOUNT_FAKE_TART") == "1" {
		fmt.Printf("args: %s\n", strings.Join(os.Args[1:], " "))
		_, _ = io.Copy(os.Stdout, os.Stdin)
		fmt.Fprintln(os.Stderr, "err")
		rc, _ := strconv.Atoi(os.Getenv("FAKE_RC"))
		os.Exit(rc)
	}
	os.Exit(m.Run())
}

// fakeTart copies this test binary to a file named tart first on PATH.
func fakeTart(t *testing.T) {
	t.Helper()
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tart"+exeSuffix), self, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTOMOUNT_FAKE_TART", "1")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

var exeSuffix = func() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}()

func TestTartRun(t *testing.T) {
	fakeTart(t)
	o, err := Tart{VM: "vm1"}.Run(context.Background(), LXC("k"), []byte("in"), "id")
	if err != nil || o.Code != 0 {
		t.Fatalf("%+v %v", o, err)
	}
	if !strings.HasPrefix(o.Stdout, "args: exec -i vm1 sudo bash -c lxc-attach -n 'k' --clear-env -- bash -c 'id'\n") || !strings.HasSuffix(o.Stdout, "in") {
		t.Errorf("stdout %q", o.Stdout)
	}
	if o.Stderr != "err\n" {
		t.Errorf("stderr %q", o.Stderr)
	}
	t.Setenv("FAKE_RC", "7")
	o, err = Tart{VM: "vm1"}.Run(context.Background(), Host, nil, "id")
	if err != nil || o.Code != 7 {
		t.Errorf("non-zero exit: %+v %v", o, err)
	}
	if _, err := (Tart{VM: "vm1"}).Run(context.Background(), Node("bad"), nil, "id"); err == nil {
		t.Error("bad node accepted")
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := (Tart{VM: "vm1"}).Run(context.Background(), Host, nil, "id"); err == nil {
		t.Error("missing tart not reported")
	}
}

func TestRecorder(t *testing.T) {
	var r Recorder
	r.Add(RecFile{Tag: "a", Node: Host, Path: "/x", Content: "1"})
	r.Add(RecFile{Tag: "b", Node: Host, Path: "/x", Content: "2"})
	r.Add(RecFile{Tag: "a", Node: LXC("k"), Path: "/x", Content: "3"})
	r.Add(RecFile{Tag: "a", Node: Host, Path: "/y", Content: "4"})
	r.Add(RecFile{Tag: "a", Node: Host, Path: "/x", Content: "5"})
	fs := r.Files()
	if len(fs) != 4 || fs[0].Content != "5" || fs[1].Content != "2" || fs[2].Content != "3" || fs[3].Content != "4" {
		t.Fatalf("%+v", fs)
	}
	fs[0].Content = "changed"
	if r.Files()[0].Content != "5" {
		t.Error("Files returned the internal slice")
	}
	dir := t.TempDir()
	if err := r.Save(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "a", "lxc-k", "x"))
	if err != nil || string(b) != "3" {
		t.Errorf("saved %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
		t.Error(err)
	}
	// A file where a directory must go.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(bad); err == nil {
		t.Error("blocked directory accepted")
	}
	// A directory where a file must go.
	bad2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bad2, "a", "host", "y"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(bad2); err == nil {
		t.Error("blocked file accepted")
	}
	if err := r.Save(filepath.Join(bad, "a", "nope")); err == nil {
		t.Error("index.json under a file accepted")
	}
}

func TestPutAndMove(t *testing.T) {
	f := newFake()
	l := NewLab(f, nil)
	l.Tag = "mit"
	if err := l.Put(context.Background(), LXC("k"), "/etc/x.conf", "640", "0:0", "hello\n"); err != nil {
		t.Fatal(err)
	}
	c := f.calls[0]
	if c.Node != LXC("k") || c.Stdin != "hello\n" || !strings.Contains(c.Script, "chmod 640 '/etc/x.conf'.new") || !strings.Contains(c.Script, "chown 0:0 ") || !strings.Contains(c.Script, "mv '/etc/x.conf'.new '/etc/x.conf'") {
		t.Errorf("%+v", c)
	}
	if fs := l.Rec.Files(); len(fs) != 1 || fs[0].Tag != "mit" || fs[0].Mode != "640" || fs[0].Owner != "0:0" || fs[0].Content != "hello\n" {
		t.Errorf("%+v", fs)
	}
	// A failed put records nothing.
	f2 := newFake()
	f2.failAt = 0
	l2 := NewLab(f2, nil)
	if err := l2.Put(context.Background(), Host, "/x", "644", "0:0", "c"); err == nil || len(l2.Rec.Files()) != 0 {
		t.Errorf("failed put: %v %v", err, l2.Rec.Files())
	}
	f2.asErr, f2.failAt = true, 1
	if err := l2.Put(context.Background(), Host, "/x", "644", "0:0", "c"); err == nil {
		t.Error("transport error swallowed")
	}

	// Move: what the first node prints in base64 is what the second reads.
	f3 := newFake()
	f3.reply = func(c call) Out {
		if c.Node == LXC("a") {
			return Out{Stdout: base64.StdEncoding.EncodeToString([]byte("secret"))}
		}
		return Out{}
	}
	l3 := NewLab(f3, nil)
	if err := l3.Move(context.Background(), LXC("a"), Host, "/src", "/dst", "600", "0:0"); err != nil {
		t.Fatal(err)
	}
	if len(f3.calls) != 2 || f3.calls[1].Node != Host || f3.calls[1].Stdin != base64.StdEncoding.EncodeToString([]byte("secret")) ||
		!strings.Contains(f3.calls[1].Script, "chmod 600 '/dst'.new") {
		t.Errorf("%+v", f3.calls)
	}
	if len(l3.Rec.Files()) != 0 {
		t.Error("a moved keytab was recorded")
	}
	everyStepFails(t, func(l *Lab) error {
		return l.Move(context.Background(), LXC("a"), Host, "/src", "/dst", "600", "0:0")
	})
}

func TestGetAndMust(t *testing.T) {
	f := newFake()
	f.reply = func(c call) Out { return Out{Stdout: "data"} }
	l := NewLab(f, nil)
	b, err := l.Get(context.Background(), Host, "/p")
	if err != nil || string(b) != "data" || f.calls[0].Script != "cat '/p'" {
		t.Errorf("%q %v %v", b, err, f.calls)
	}
	f.failAt = 1
	if _, err := l.Get(context.Background(), Host, "/p"); err == nil {
		t.Error("failed cat accepted")
	}
	f.failAt, f.asErr = 2, true
	if _, err := l.Must(context.Background(), Host, "x"); err == nil {
		t.Error("transport error accepted")
	}
}

func TestWait(t *testing.T) {
	if err := Wait(context.Background(), time.Millisecond); err != nil {
		t.Error(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Wait(ctx, time.Hour); err == nil {
		t.Error("cancelled wait returned nil")
	}
}

func TestNewLabLogf(t *testing.T) {
	var lines []string
	l := NewLab(newFake(), func(f string, a ...any) { lines = append(lines, f) })
	if _, err := l.Sh(context.Background(), Host, "id"); err != nil || len(lines) != 1 {
		t.Errorf("%v %v", err, lines)
	}
	// A nil logger is replaced by a no-op.
	if _, err := NewLab(newFake(), nil).Sh(context.Background(), Host, "id"); err != nil {
		t.Error(err)
	}
}

func TestBootstrapEveryStepFails(t *testing.T) {
	everyStepFails(t, func(l *Lab) error { return l.Bootstrap(context.Background()) })
}

func TestContainerEveryStepFails(t *testing.T) {
	everyStepFails(t, func(l *Lab) error {
		return l.Container(context.Background(), "c", "10.0.3.9", "c.poc.test", MITIP, "lxc.mount.entry = a b\n")
	})
	// Without extra config there is one step fewer.
	a, b := newFake(), newFake()
	if err := NewLab(a, nil).Container(context.Background(), "c", "10.0.3.9", "c.poc.test", MITIP, ""); err != nil {
		t.Fatal(err)
	}
	if err := NewLab(b, nil).Container(context.Background(), "c", "10.0.3.9", "c.poc.test", MITIP, "x\n"); err != nil {
		t.Fatal(err)
	}
	if len(b.calls) != len(a.calls)+1 {
		t.Errorf("%d vs %d calls", len(a.calls), len(b.calls))
	}
	// The config is appended only once: the guard greps its first line.
	if !strings.Contains(b.calls[1].Script, "grep -qF 'x' /var/lib/lxc/c/config || printf '%s' 'x\n' >> /var/lib/lxc/c/config") {
		t.Errorf("%s", b.calls[1].Script)
	}
}

func TestSambaEveryStepFails(t *testing.T) {
	everyStepFails(t, func(l *Lab) error { return l.Samba(context.Background(), MIT()) })
}

func TestSambaConfigureEveryStepFails(t *testing.T) {
	everyStepFails(t, func(l *Lab) error { return l.SambaConfigure(context.Background(), true) })
	f := newFake()
	if err := NewLab(f, nil).SambaConfigure(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.calls[1].Stdin, `"WORKGROUP\root/client.poc.test"`) {
		t.Errorf("quoted map not installed: %q", f.calls[1].Stdin)
	}
	if err := NewLab(f, nil).SambaConfigure(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.calls[len(f.calls)-3].Stdin, `"`) {
		t.Errorf("unquoted map has quotes")
	}
}

func TestUseKDCEveryStepFailsButTheCleanup(t *testing.T) {
	for _, k := range []KDC{MIT(), Heimdal()} {
		base := newFake()
		if err := NewLab(base, nil).UseKDC(context.Background(), k); err != nil {
			t.Fatal(err)
		}
		for i := range base.calls {
			f := newFake()
			f.failAt = i
			err := NewLab(f, nil).UseKDC(context.Background(), k)
			isCleanup := strings.Contains(base.calls[i].Script, "umount -a -t cifs")
			if isCleanup && err != nil {
				t.Errorf("the cleanup (call %d) may fail: %v", i, err)
			}
			if !isCleanup && err == nil {
				t.Errorf("%s: call %d (%q) failed and UseKDC returned nil", k.Name, i, firstLine(base.calls[i].Script))
			}
			f2 := newFake()
			f2.failAt, f2.asErr = i, true
			if err := NewLab(f2, nil).UseKDC(context.Background(), k); err == nil {
				t.Errorf("%s: transport error at call %d swallowed", k.Name, i)
			}
		}
	}
	// The keytabs: the right principal to the right node, with the right mode.
	f := newFake()
	if err := NewLab(f, nil).UseKDC(context.Background(), MIT()); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, c := range f.calls {
		all.WriteString(string(c.Node) + " " + c.Script + "\n")
	}
	for _, want := range []string{
		"ktadd -k /root/keytabs/cifs.keytab cifs/samba.poc.test",
		"chmod 600 '/etc/samba/cifs.keytab'.new",
		"chmod 600 '/etc/krb5.keytab'.new",
		"chmod 400 '/etc/krb5/alice.keytab'.new",
		"chown 2001:2001 '/etc/krb5/alice.keytab'.new",
	} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(all.String(), "bob.keytab") {
		t.Error("bob logs in with a password: a keytab would have changed it")
	}
}

func TestLogsAreRead(t *testing.T) {
	f := newFake()
	f.reply = func(c call) Out { return Out{Stdout: c.Script} }
	l := NewLab(f, nil)
	s, err := l.KDCLog(context.Background(), MIT())
	if err != nil || s != "journalctl -u krb5-kdc --no-pager -o cat" || f.calls[0].Node != LXC("kdc-mit") {
		t.Errorf("%q %v %v", s, err, f.calls)
	}
	s, err = l.SmbdLog(context.Background())
	if err != nil || s != "cat /var/log/samba/log.smbd" || f.calls[1].Node != LXC("samba") {
		t.Errorf("%q %v", s, err)
	}
	f.failAt, f.asErr = 2, true
	if _, err := l.KDCLog(context.Background(), MIT()); err == nil {
		t.Error("KDC log transport error swallowed")
	}
}

func TestKDCSetupEveryStepFails(t *testing.T) {
	for _, k := range []KDC{MIT(), Heimdal()} {
		k := k
		everyStepFails(t, func(l *Lab) error { return k.Setup(context.Background(), l) })
	}
}

func TestKDCSetupToleratesExistingPrincipals(t *testing.T) {
	for _, k := range []KDC{MIT(), Heimdal()} {
		f := newFake()
		f.reply = func(c call) Out {
			if strings.Contains(c.Script, "add") {
				return Out{Code: 1, Stderr: "Principal or policy already exists while creating"}
			}
			return Out{}
		}
		if err := k.Setup(context.Background(), NewLab(f, nil)); err != nil {
			t.Errorf("%s: %v", k.Name, err)
		}
		f.reply = func(c call) Out {
			if strings.Contains(c.Script, "add") {
				return Out{Code: 1, Stderr: "something else"}
			}
			return Out{}
		}
		if err := k.Setup(context.Background(), NewLab(f, nil)); err == nil {
			t.Errorf("%s: an unknown add failure was tolerated", k.Name)
		}
	}
}

func TestKDCScripts(t *testing.T) {
	m, h := MIT(), Heimdal()
	if m.Node() != LXC("kdc-mit") || h.Node() != LXC("kdc-heimdal") || m.LogCmd() == h.LogCmd() || h.LogCmd() != "cat '/var/log/heimdal-kdc.log'" {
		t.Error("nodes or logs")
	}
	for _, c := range []struct{ got, want string }{
		{m.AddScript("a", ""), "kadmin.local -q 'addprinc -randkey a'"},
		{m.AddScript("a", "pw"), "kadmin.local -q 'addprinc -pw pw a'"},
		{m.KeytabScript("/k", "a"), "rm -f '/k'; kadmin.local -q 'ktadd -k /k a'"},
		{m.MaxLifeScript("a", "3min"), `kadmin.local -q 'modprinc -maxlife "3min" a'`},
		{h.AddScript("a", ""), "kadmin -l add --random-key --use-defaults 'a'"},
		{h.AddScript("a", "pw"), "kadmin -l add --password='pw' --use-defaults 'a'"},
		{h.KeytabScript("/k", "a"), "rm -f '/k'; kadmin -l ext_keytab -k '/k' 'a'"},
		{h.MaxLifeScript("a", "3m"), "kadmin -l modify --max-ticket-life='3m' 'a'"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	var names []string
	for _, p := range Principals() {
		names = append(names, p.Name)
	}
	if got := strings.Join(names, " "); got != "cifs/samba.poc.test root/client.poc.test svc-partage alice bob" {
		t.Errorf("principals %s", got)
	}
	if !containsAny("a b", "x", "b") || containsAny("a b", "x", "y") || containsAny("a b") {
		t.Error("containsAny")
	}
}

func TestConfigs(t *testing.T) {
	for _, c := range []struct{ name, got, want string }{
		{"smb standalone", SmbConf(), "server role = standalone server"},
		{"smb keytab", SmbConf(), "dedicated keytab file = /etc/samba/cifs.keytab"},
		{"smb kerberos method", SmbConf(), "kerberos method = dedicated keytab"},
		{"smb map", SmbConf(), "username map = /etc/samba/usermap"},
		{"smb guest", SmbConf(), "map to guest = never"},
		{"smb ntlm", SmbConf(), "ntlm auth = disabled"},
		{"smb share", SmbConf(), "[partage]\n  path = /srv/partage\n"},
		{"krb5 rdns", KRB5Conf(), "rdns = false"},
		{"krb5 ccache", KRB5Conf(), "default_ccache_name = FILE:/tmp/krb5cc_%{uid}"},
		{"mit kdc", MITKDCConf(), "max_life = 10h 0m 0s"},
		{"heimdal", HeimdalKRB5Conf(), "kdc = FILE:/var/log/heimdal-kdc.log"},
		{"hosts", HostsFile("10.0.3.12"), "10.0.3.12 kdc.poc.test kdc\n"},
		{"hosts client", HostsFile("10.0.3.12"), "10.0.3.1 client.poc.test client\n"},
		{"hosts samba", HostsFile("10.0.3.12"), "10.0.3.13 samba.poc.test samba\n"},
		{"networkd", NetworkdFile("10.0.3.5"), "Address=10.0.3.5/24\nGateway=10.0.3.1\n"},
		{"idmap", LXCIdmap, "lxc.idmap = u 0 100000 65536\nlxc.idmap = g 0 100000 65536\n"},
		{"usermap plain", UserMap(false), "partage = WORKGROUP\\root/client.poc.test WORKGROUP\\svc-partage\n"},
		{"usermap quoted", UserMap(true), "partage = \"WORKGROUP\\root/client.poc.test\" WORKGROUP\\svc-partage\n"},
		{"spnego", SpnegoConf(""), "create  cifs.spnego    * * /usr/sbin/cifs.upcall --keytab=/etc/krb5.keytab %k\n"},
		{"spnego wrapped", SpnegoConf("/usr/bin/faketime -f +10m"), "* * /usr/bin/faketime -f +10m /usr/sbin/cifs.upcall --keytab"},
		{"fstab", FstabLine(), "//samba.poc.test/partage /mnt/fstab cifs sec=krb5,vers=3.1.1,cruid=0,uid=1000,gid=1000,username=root/client.poc.test@POC.TEST,noauto,x-systemd.automount,x-systemd.idle-timeout=60,_netdev 0 0\n"},
		{"autofs master", AutofsMaster(), "/mnt/autofs /etc/auto.poc --timeout=60\n"},
		{"autofs map", AutofsMap(), "partage -fstype=cifs,sec=krb5,vers=3.1.1,cruid=0,uid=1000,gid=1000,username=root/client.poc.test@POC.TEST ://samba.poc.test/partage\n"},
		{"opts", MountOpts(), "sec=krb5,vers=3.1.1,cruid=0,uid=1000,gid=1000"},
		{"opts extra", MountOpts("multiuser", "noperm"), "gid=1000,multiuser,noperm"},
		{"service", RenewService(), "ExecStart=/usr/bin/kinit -k -t /etc/krb5/svc-partage.keytab svc-partage@POC.TEST\n"},
		{"service ccache", RenewService(), "Environment=KRB5CCNAME=FILE:/tmp/krb5cc_0\n"},
		{"timer", RenewTimer("90s"), "OnUnitActiveSec=90s\n"},
	} {
		if !strings.Contains(c.got, c.want) {
			t.Errorf("%s: %q does not contain %q", c.name, c.got, c.want)
		}
	}
	if strings.Contains(UserMap(false), `"`) {
		t.Error("plain map has quotes")
	}
	if got := MountOpts(); strings.Contains(got, "multiuser") || strings.Contains(got, "ntlm") {
		t.Errorf("opts %q", got)
	}
}
