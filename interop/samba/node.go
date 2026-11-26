// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Network is the user-defined Docker network every container joins: it gives
// them stable names that resolve to each other, which Kerberos needs.
const Network = "go-authn-kdc-interop"

// Out is what a command printed and how it ended.
type Out struct {
	Stdout, Stderr []byte
	Code           int
}

func (o Out) String() string {
	return strings.TrimSpace(string(o.Stdout) + string(o.Stderr))
}

// docker runs the docker CLI. It is a variable so that tests replace it with
// a fake that fails on demand: every refusal below is then asserted without
// Docker.
var docker = runDocker

// dockerBin is the program runDocker executes; tests point it at stand-ins.
var dockerBin = "docker"

func runDocker(ctx context.Context, stdin []byte, args ...string) (Out, error) {
	cmd := exec.CommandContext(ctx, dockerBin, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	o := Out{Stdout: so.Bytes(), Stderr: se.Bytes()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		o.Code = ee.ExitCode()
		return o, nil
	}
	return o, err
}

// Images are the three images built from docker/.
var Images = []string{"samba", "mit", "heimdal"}

// ImageName is the tag of an image of Images.
func ImageName(role string) string { return "go-authn-kdc-interop-" + role }

// Build builds the images from dockerDir (cached by Docker) and creates the
// network if it is not there.
func Build(ctx context.Context, dockerDir string) error {
	for _, role := range Images {
		o, err := docker(ctx, nil, "build", "-q", "-t", ImageName(role), "-f", filepath.Join(dockerDir, "Dockerfile."+role), dockerDir)
		if err != nil || o.Code != 0 {
			return fmt.Errorf("docker build %s: %v %s", role, err, o)
		}
	}
	if o, _ := docker(ctx, nil, "network", "inspect", Network); o.Code != 0 {
		if o, err := docker(ctx, nil, "network", "create", Network); err != nil || o.Code != 0 {
			return fmt.Errorf("docker network create: %v %s", err, o)
		}
	}
	return nil
}

// Node is a running container, driven with `docker exec`. Everything runs as
// root inside it; nothing touches the host but the one address it reaches the
// host on.
type Node struct{ Name string }

// StartNode (re)creates a container named name, reachable on Network as host.
func StartNode(ctx context.Context, name, role, host string) (Node, error) {
	_, _ = docker(ctx, nil, "rm", "-f", name)
	o, err := docker(ctx, nil, "run", "-d", "--name", name, "--network", Network,
		"--hostname", host, "--network-alias", host,
		"--add-host", "host.docker.internal:host-gateway",
		ImageName(role), "sleep", "infinity")
	if err != nil || o.Code != 0 {
		return Node{}, fmt.Errorf("docker run %s: %v %s", name, err, o)
	}
	return Node{name}, nil
}

// Remove deletes the container.
func (n Node) Remove() {
	_, _ = docker(context.Background(), nil, "rm", "-f", n.Name)
}

// Run executes args in the container, with stdin if non-nil. A command that
// runs and fails is not an error: its Code says so.
func (n Node) Run(ctx context.Context, stdin []byte, args ...string) (Out, error) {
	a := []string{"exec"}
	if stdin != nil {
		a = append(a, "-i")
	}
	a = append(a, n.Name)
	return docker(ctx, stdin, append(a, args...)...)
}

// Sudo is Run: the container's user is root.
func (n Node) Sudo(ctx context.Context, stdin []byte, args ...string) (Out, error) {
	return n.Run(ctx, stdin, args...)
}

// Spawn starts a long-lived process in the container and returns.
func (n Node) Spawn(ctx context.Context, args ...string) error {
	o, err := docker(ctx, nil, append([]string{"exec", "-d", n.Name}, args...)...)
	if err != nil || o.Code != 0 {
		return fmt.Errorf("spawning %v: %v %s", args, err, o)
	}
	return nil
}

// Must is Sudo that turns a non-zero exit into an error carrying the output.
func (n Node) Must(ctx context.Context, stdin []byte, args ...string) (Out, error) {
	o, err := n.Run(ctx, stdin, args...)
	if err == nil && o.Code != 0 {
		err = fmt.Errorf("%s: exit %d: %s", strings.Join(args, " "), o.Code, o)
	}
	return o, err
}

// WriteFile installs data at path with the given mode.
func (n Node) WriteFile(ctx context.Context, path, mode string, data []byte) error {
	if _, err := n.Must(ctx, nil, "mkdir", "-p", filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := n.Must(ctx, data, "tee", path); err != nil {
		return err
	}
	_, err := n.Must(ctx, nil, "chmod", mode, path)
	return err
}

// ReadFile returns the bytes of a file.
func (n Node) ReadFile(ctx context.Context, path string) ([]byte, error) {
	o, err := n.Must(ctx, nil, "cat", path)
	return o.Stdout, err
}
