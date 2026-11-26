package automount

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// e2eVM is the Tart VM the matrix drives; AUTOMOUNT_VM overrides it.
func e2eVM() string {
	if v := os.Getenv("AUTOMOUNT_VM"); v != "" {
		return v
	}
	return "automount-debian13"
}

// outDir is where matrix.md, matrix.json and the installed files go.
func outDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("AUTOMOUNT_OUT"); d != "" {
		return d
	}
	d, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(d, "go-authn-kdc-automount-interop")
}

func e2eLab(t *testing.T) (*Lab, context.Context) {
	t.Helper()
	if os.Getenv("AUTOMOUNT_INTEROP") != "1" {
		t.Skip("end-to-end proof: needs a Tart VM, set AUTOMOUNT_INTEROP=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	t.Cleanup(cancel)
	return NewLab(Tart{VM: e2eVM()}, t.Logf), ctx
}

// TestSetup builds the lab: the VM, the KDC containers, the Samba container.
func TestSetup(t *testing.T) {
	l, ctx := e2eLab(t)
	if err := l.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	for _, k := range []KDC{MIT(), Heimdal()} {
		if err := l.Container(ctx, k.Container, k.IP, KDCFQDN, k.IP, ""); err != nil {
			t.Fatal(err)
		}
		if err := k.Setup(ctx, l); err != nil {
			t.Fatalf("%s: %v", k.Name, err)
		}
	}
	if err := l.Samba(ctx, MIT()); err != nil {
		t.Fatal(err)
	}
}
