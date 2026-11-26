// Package automount is the harness of an end-to-end proof: a Linux client that
// AUTOMOUNTS a Samba share with Kerberos and no human kinit.
//
// Everything runs inside one Debian 13 VM (a Tart VM here, which stands in for
// the Proxmox host AND is the client). The KDC and the Samba server are
// unprivileged LXC containers of that VM (idmap 100000, like a Proxmox CT).
// The harness is driven from the Mac through `tart exec`; this file is the
// transport, the other files are the scenarios.
//
// Normal CI never touches a VM: the end-to-end test needs AUTOMOUNT_INTEROP=1.
package automount

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Node says where a script runs.
//
//	"host"        the VM itself, as root: the Proxmox host and the client
//	"lxc:NAME"    inside the container NAME, as its root
//	"user:NAME"   on the VM, as the Unix user NAME (no login shell)
type Node string

// Host is the VM.
const Host Node = "host"

// LXC is the node of the container name.
func LXC(name string) Node { return Node("lxc:" + name) }

// User is the node of the VM's Unix user name.
func User(name string) Node { return Node("user:" + name) }

// Out is the outcome of one script.
type Out struct {
	Code           int
	Stdout, Stderr string
}

// String is the combined output, for evidence lines.
func (o Out) String() string {
	return strings.TrimRight(o.Stdout+o.Stderr, "\n")
}

// Exec runs a script on a node with an optional stdin.
type Exec interface {
	Run(ctx context.Context, n Node, stdin []byte, script string) (Out, error)
}

// Quote single-quotes s for a POSIX shell.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Wrap returns the script that the VM's root shell must run for a node.
func Wrap(n Node, script string) (string, error) {
	switch {
	case n == Host:
		return script, nil
	case strings.HasPrefix(string(n), "lxc:"):
		return "lxc-attach -n " + Quote(string(n)[4:]) + " --clear-env -- bash -c " + Quote(script), nil
	case strings.HasPrefix(string(n), "user:"):
		return "runuser -u " + Quote(string(n)[5:]) + " -- bash -c " + Quote(script), nil
	}
	return "", fmt.Errorf("unknown node %q", n)
}

// Tart runs scripts in a Tart VM through its guest agent.
type Tart struct{ VM string }

// Run implements Exec.
func (t Tart) Run(ctx context.Context, n Node, stdin []byte, script string) (Out, error) {
	w, err := Wrap(n, script)
	if err != nil {
		return Out{}, err
	}
	cmd := exec.CommandContext(ctx, "tart", "exec", "-i", t.VM, "sudo", "bash", "-c", w)
	cmd.Stdin = bytes.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	o := Out{Stdout: so.String(), Stderr: se.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		o.Code = ee.ExitCode()
		return o, nil
	}
	return o, err
}

// RecFile is one file the harness installed: the exact bytes that were in
// place when the matrix ran, which the document quotes verbatim.
type RecFile struct {
	Tag     string // the scenario family, "mit", "heimdal", "common"
	Node    Node
	Path    string
	Mode    string
	Owner   string
	Content string
}

// Recorder keeps the installed files, the last write of a (tag, node, path)
// winning, in first-write order.
type Recorder struct {
	mu    sync.Mutex
	files []RecFile
}

// Add records f.
func (r *Recorder) Add(f RecFile) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.files {
		if r.files[i].Tag == f.Tag && r.files[i].Node == f.Node && r.files[i].Path == f.Path {
			r.files[i] = f
			return
		}
	}
	r.files = append(r.files, f)
}

// Files is a copy of the recorded files.
func (r *Recorder) Files() []RecFile {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RecFile(nil), r.files...)
}

// Save writes every file under dir/<tag>/<node>/<path>, plus index.json.
func (r *Recorder) Save(dir string) error {
	fs := r.Files()
	for _, f := range fs {
		node := strings.ReplaceAll(string(f.Node), ":", "-")
		p := filepath.Join(dir, f.Tag, node, filepath.FromSlash(strings.TrimPrefix(f.Path, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.json"), b, 0o644)
}

// Lab is the VM plus its recorder.
type Lab struct {
	X   Exec
	Rec *Recorder
	// Tag labels the files recorded from now on.
	Tag string
	// Logf receives one line per script, for the test log.
	Logf func(format string, args ...any)
}

// NewLab returns a lab over x.
func NewLab(x Exec, logf func(string, ...any)) *Lab {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Lab{X: x, Rec: &Recorder{}, Tag: "common", Logf: logf}
}

// Sh runs a script and returns its outcome, whatever its exit code.
func (l *Lab) Sh(ctx context.Context, n Node, script string) (Out, error) {
	return l.sh(ctx, n, nil, script)
}

func (l *Lab) sh(ctx context.Context, n Node, stdin []byte, script string) (Out, error) {
	start := time.Now()
	o, err := l.X.Run(ctx, n, stdin, script)
	first := strings.SplitN(strings.TrimSpace(script), "\n", 2)[0]
	l.Logf("[%s] %s -> rc=%d (%s)", n, first, o.Code, time.Since(start).Round(time.Millisecond))
	return o, err
}

// Must runs a script and fails on a non-zero exit.
func (l *Lab) Must(ctx context.Context, n Node, script string) (Out, error) {
	o, err := l.Sh(ctx, n, script)
	if err != nil {
		return o, fmt.Errorf("%s: %w", n, err)
	}
	if o.Code != 0 {
		return o, fmt.Errorf("%s: %q exited %d: %s", n, strings.SplitN(script, "\n", 2)[0], o.Code, o)
	}
	return o, nil
}

// Put installs a file (mkdir -p, atomic rename, mode, owner) and records it.
func (l *Lab) Put(ctx context.Context, n Node, path, mode, owner, content string) error {
	s := fmt.Sprintf("set -e; mkdir -p \"$(dirname %[1]s)\"; cat > %[1]s.new; chmod %[2]s %[1]s.new; chown %[3]s %[1]s.new; mv %[1]s.new %[1]s",
		Quote(path), mode, owner)
	o, err := l.sh(ctx, n, []byte(content), s)
	if err != nil {
		return err
	}
	if o.Code != 0 {
		return fmt.Errorf("put %s on %s: %s", path, n, o)
	}
	l.Rec.Add(RecFile{Tag: l.Tag, Node: n, Path: path, Mode: mode, Owner: owner, Content: content})
	return nil
}

// Get reads a file.
func (l *Lab) Get(ctx context.Context, n Node, path string) ([]byte, error) {
	o, err := l.Must(ctx, n, "cat "+Quote(path))
	return []byte(o.Stdout), err
}

// Move copies a file between nodes: what `pct pull` followed by `pct push`
// does on a Proxmox host. The bytes pass through the harness, never a file on
// the host. The content is not recorded (a keytab is a secret).
func (l *Lab) Move(ctx context.Context, from, to Node, src, dst, mode, owner string) error {
	b64, err := l.Must(ctx, from, "base64 -w0 < "+Quote(src))
	if err != nil {
		return err
	}
	s := fmt.Sprintf("set -e; mkdir -p \"$(dirname %[1]s)\"; base64 -d > %[1]s.new; chmod %[2]s %[1]s.new; chown %[3]s %[1]s.new; mv %[1]s.new %[1]s",
		Quote(dst), mode, owner)
	o, err := l.sh(ctx, to, []byte(b64.Stdout), s)
	if err != nil {
		return err
	}
	if o.Code != 0 {
		return fmt.Errorf("move %s to %s on %s: %s", src, dst, to, o)
	}
	return nil
}
