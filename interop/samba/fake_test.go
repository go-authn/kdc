// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
)

// fakeDocker replaces the docker CLI. It answers every call as a success,
// except call number failAt, which fails as a transport error or as a
// non-zero exit; the failure carries its call number so a test can assert
// WHICH refusal spoke.
type fakeDocker struct {
	calls      [][]string
	failAt     int
	transport  bool
	files      map[string][]byte // what `cat <path>` prints
	idMissing  bool              // `id alice` exits 1: the user must be created
	netMissing bool              // `network inspect` exits 1
	pingFails  bool              // smbd never answers
	kadmin     string            // what kadmin prints
}

func (f *fakeDocker) do(_ context.Context, _ []byte, args ...string) (Out, error) {
	i := len(f.calls)
	f.calls = append(f.calls, args)
	if i == f.failAt {
		if f.transport {
			return Out{}, fmt.Errorf("transport-%d", i)
		}
		return Out{Code: 1, Stderr: []byte(fmt.Sprintf("exit-%d", i))}, nil
	}
	has := func(w string) bool { return slices.Contains(args, w) }
	switch {
	case has("cat"):
		return Out{Stdout: f.files[args[len(args)-1]]}, nil
	case has("klist"):
		return Out{Stdout: []byte("Ticket cache\n\tcifs/smbhost.interop.test@X\n\tEtype (skey, tkt): aes256, aes256\n")}, nil
	case has("smbclient"):
		return Out{Stdout: []byte("hello.txt N 6")}, nil
	case has("kadmin.local"), has("kadmin.heimdal"):
		return Out{Stdout: []byte(f.kadmin)}, nil
	case has("id") && f.idMissing:
		return Out{Code: 1}, nil
	case has("inspect") && f.netMissing:
		return Out{Code: 1}, nil
	case has("ping") && f.pingFails:
		return Out{Code: 1}, nil
	}
	return Out{}, nil
}

// install makes docker() the fake for the test; pause is zeroed.
func install(t *testing.T, f *fakeDocker) {
	t.Helper()
	oldD, oldP := docker, pause
	docker, pause = f.do, 0
	t.Cleanup(func() { docker, pause = oldD, oldP })
}

// tolerated says whether the code under test ignores the failure of this call
// by design: cleanup, probes whose failure selects another path.
func tolerated(args []string, transport bool) bool {
	for _, w := range []string{"rm", "kdestroy", "klist", "inspect", "dpkg-query"} {
		if slices.Contains(args, w) {
			return true
		}
	}
	if slices.Contains(args, "ping") { // smbd is probed again
		return true
	}
	if slices.Contains(args, logPath) { // the log is evidence, read if it can be
		return true
	}
	if !transport {
		// a command that runs and fails is a result, not an error
		return slices.Contains(args, "smbclient") || slices.Contains(args, "id")
	}
	return false
}

// failEachCall runs fn once clean, then once per call and per failure mode with
// that call failing, and asserts that every call that is not tolerated makes
// fn fail with that call's own message.
func failEachCall(t *testing.T, base fakeDocker, fn func(context.Context) error) {
	t.Helper()
	clean := base
	clean.failAt = -1
	install(t, &clean)
	if err := fn(context.Background()); err != nil {
		t.Fatalf("with no failure: %v", err)
	}
	n := len(clean.calls)
	if n == 0 {
		t.Fatal("the function made no docker call")
	}
	for i := 0; i < n; i++ {
		for _, transport := range []bool{true, false} {
			f := base
			f.failAt, f.transport = i, transport
			install(t, &f)
			err := fn(context.Background())
			if tolerated(clean.calls[i], transport) {
				continue
			}
			want := fmt.Sprintf("exit-%d", i)
			if transport {
				want = fmt.Sprintf("transport-%d", i)
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("call %d %v (transport=%v): error %v, want it to contain %q", i, clean.calls[i], transport, err, want)
			}
		}
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildRefusals(t *testing.T) {
	for _, net := range []bool{false, true} {
		failEachCall(t, fakeDocker{netMissing: net}, func(ctx context.Context) error { return Build(ctx, "docker") })
	}
}

func TestStartNodeRefusals(t *testing.T) {
	failEachCall(t, fakeDocker{}, func(ctx context.Context) error {
		_, err := StartNode(ctx, "n", "samba", "h")
		return err
	})
}

func TestNodeHelpersRefusals(t *testing.T) {
	n := Node{Name: "n"}
	failEachCall(t, fakeDocker{files: map[string][]byte{"/p": []byte("x")}}, func(ctx context.Context) error {
		if err := n.Spawn(ctx, "x"); err != nil {
			return err
		}
		if err := n.WriteFile(ctx, "/d/p", "600", []byte("x")); err != nil {
			return err
		}
		b, err := n.ReadFile(ctx, "/p")
		if err == nil && string(b) != "x" {
			return fmt.Errorf("read %q", b)
		}
		return err
	})
	var o Out
	o.Stdout, o.Stderr = []byte(" a\n"), []byte("b ")
	if o.String() != "a\nb" {
		t.Fatalf("Out.String = %q", o.String())
	}
	f := &fakeDocker{failAt: -1}
	install(t, f)
	n.Remove()
	if _, err := n.Sudo(context.Background(), []byte("in"), "id"); err != nil {
		t.Fatal(err)
	}
	if got := f.calls[len(f.calls)-1]; !slices.Equal(got, []string{"exec", "-i", "n", "id"}) {
		t.Fatalf("Sudo with stdin ran %v", got)
	}
}

func TestKDCStartRefusals(t *testing.T) {
	files := map[string][]byte{"/tmp/mit-cifs.keytab": []byte("k"), "/tmp/heimdal-cifs.keytab": []byte("k")}
	failEachCall(t, fakeDocker{files: files}, func(ctx context.Context) error {
		m := &MITKDC{Realm: "R"}
		defer m.Stop()
		env, err := m.Start(ctx)
		if err == nil && (env.Realm != "R" || env.KDC != mitHost || string(env.Keytab) != "k") {
			err = fmt.Errorf("env %+v", env)
		}
		return err
	})
	failEachCall(t, fakeDocker{files: files}, func(ctx context.Context) error {
		h := &HeimdalKDC{Realm: "R"}
		defer h.Stop()
		env, err := h.Start(ctx)
		if err == nil && (env.Realm != "R" || env.KDC != heimdalHost || string(env.Keytab) != "k") {
			err = fmt.Errorf("env %+v", env)
		}
		return err
	})
}

func TestKadminErrorTextIsRefused(t *testing.T) {
	f := &fakeDocker{failAt: -1, kadmin: "kadmin: Error: boom"}
	install(t, f)
	if _, err := (&MITKDC{Realm: "R"}).Start(context.Background()); err == nil || !strings.Contains(err.Error(), "kadmin.local") {
		t.Fatalf("MIT: %v", err)
	}
	if _, err := (&HeimdalKDC{Realm: "R"}).Start(context.Background()); err == nil || !strings.Contains(err.Error(), "kadmin.heimdal -l") {
		t.Fatalf("Heimdal: %v", err)
	}
}

func TestKDCVersionAndNames(t *testing.T) {
	f := &fakeDocker{failAt: -1}
	install(t, f)
	m, h := &MITKDC{}, &HeimdalKDC{}
	_ = m.Version(context.Background())
	_ = h.Version(context.Background())
	if got := f.calls[0][len(f.calls[0])-1]; got != "krb5-kdc" {
		t.Fatalf("MIT version asked for %q", got)
	}
	if got := f.calls[1][len(f.calls[1])-1]; got != "heimdal-kdc" {
		t.Fatalf("Heimdal version asked for %q", got)
	}
	if (&GoKDC{}).Name() == "" || m.Name() == "" || h.Name() == "" || (&GoKDC{}).Version(context.Background()) == "" {
		t.Fatal("a KDC has no name or version")
	}
}

func TestGoKDC(t *testing.T) {
	g := &GoKDC{Realm: "GOAUTHN.TEST", listen: "127.0.0.1:0"}
	env, err := g.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	if !strings.HasPrefix(env.KDC, "host.docker.internal:") || env.Realm != "GOAUTHN.TEST" || len(env.Keytab) == 0 {
		t.Fatalf("env %+v", env)
	}
	(&GoKDC{}).Stop() // never started: nothing to close
}

func TestGoKDCRefusals(t *testing.T) {
	if err := startNoPanic(t, &GoKDC{Realm: "R", etype: 9999}); err == nil || !strings.Contains(err.Error(), "key of krbtgt/R") {
		t.Fatalf("an unknown etype: %v", err)
	}
	if err := startNoPanic(t, &GoKDC{Realm: "R", listen: "no-such-host.invalid:x"}); err == nil {
		t.Fatal("an address that cannot be listened on was accepted")
	}
	if err := startNoPanic(t, &GoKDC{Realm: ""}); err == nil || !strings.Contains(err.Error(), "kdc.New") {
		t.Fatalf("an empty realm: %v", err)
	}
}

func TestGoKDCPACRow(t *testing.T) {
	if (&GoKDC{PAC: true}).Name() == (&GoKDC{}).Name() || !strings.Contains((&GoKDC{PAC: true}).Name(), "PAC") {
		t.Error("the PAC row is not named apart from the default")
	}
	g := &GoKDC{Realm: "GOAUTHN.TEST", listen: "127.0.0.1:0", PAC: true}
	if _, err := g.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.Stop()
	old := newAttributes
	t.Cleanup(func() { newAttributes = old })
	boom := fmt.Errorf("attributes refused")
	newAttributes = func(...directory.Attribute) (directory.Attributes, error) { return directory.Attributes{}, boom }
	if err := startNoPanic(t, &GoKDC{Realm: "GOAUTHN.TEST", listen: "127.0.0.1:0", PAC: true}); err != boom {
		t.Errorf("a refused attribute set: %v", err)
	}
}

func readFixture(name string) ([]byte, error) { return os.ReadFile("testdata/" + name) }

func TestRunDockerOutcomes(t *testing.T) {
	old := dockerBin
	t.Cleanup(func() { dockerBin = old })
	ctx := context.Background()

	dockerBin = "cat" // echoes stdin: stdout and stdin are wired
	o, err := runDocker(ctx, []byte("hi"))
	if err != nil || o.Code != 0 || string(o.Stdout) != "hi" {
		t.Fatalf("cat: %+v %v", o, err)
	}
	dockerBin = "false" // runs and fails: a result, not an error
	o, err = runDocker(ctx, nil)
	if err != nil || o.Code != 1 {
		t.Fatalf("false: %+v %v", o, err)
	}
	dockerBin = "no-such-program-for-the-interop-test" // cannot run: an error
	if _, err = runDocker(ctx, nil); err == nil {
		t.Fatal("a missing program was not an error")
	}
}

// startNoPanic runs Start and reports a panic as such, so that a refusal
// removed by mutation is caught by an assertion.
func startNoPanic(t *testing.T, g *GoKDC) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Start panicked instead of refusing: %v", r)
			err = fmt.Errorf("panic")
		}
	}()
	_, err = g.Start(context.Background())
	return err
}
