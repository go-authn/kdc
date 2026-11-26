// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSambaMatrix puts the same Samba container behind each KDC and records
// the outcome.
//
//	SAMBA_INTEROP=1 go test ./interop/samba -run TestSambaMatrix -v -timeout 30m
//
// It builds three images from docker/ (cached by Docker), creates the user
// network Network, and removes every container it starts.
func TestSambaMatrix(t *testing.T) {
	if os.Getenv("SAMBA_INTEROP") != "1" {
		t.Skip("set SAMBA_INTEROP=1 (needs Docker, see interop/samba/README.md)")
	}
	outDir := os.Getenv("SAMBA_INTEROP_OUT")
	if outDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			t.Fatal(err)
		}
		outDir = filepath.Join(base, "go-authn-kdc-samba-interop")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	if err := Build(ctx, "docker"); err != nil {
		t.Fatal(err)
	}

	// "none" is the baseline: a standalone server. The control gives the
	// server the role Samba expects a PAC from, to show what the baseline's
	// role is what lets a PAC-less ticket through.
	relaxations := []Relaxation{{Name: "none"}, {Name: "control: member server", Role: "member server"}}
	// The PAC row: a member server (it wants a PAC), with winbindd running and
	// the domain SID the KDC puts in LOGON_INFO set as its own. Only the KDC
	// configured to issue a PAC is put behind it.
	memberPAC := Relaxation{
		Name: "member server + winbindd + domain SID", Role: "member server",
		Line:    "idmap config * : backend = tdb\nidmap config * : range = 3000-7999",
		Setup:   [][]string{{"net", "setdomainsid", PACDomainSID}},
		Daemons: [][]string{{"winbindd", "--foreground", "--no-process-group"}},
	}
	kdcs := []KDC{&GoKDC{Realm: "GOAUTHN.TEST"}, &GoKDC{Realm: "GOAUTHNPAC.TEST", PAC: true},
		&MITKDC{Realm: "MIT.TEST"}, &HeimdalKDC{Realm: "HEIMDAL.TEST"}}
	var rows []Result
	for _, k := range kdcs {
		relaxations := relaxations
		if g, ok := k.(*GoKDC); ok && g.PAC {
			relaxations = []Relaxation{memberPAC}
		}
		t.Run(strings.ReplaceAll(k.Name(), "/", "_"), func(t *testing.T) {
			defer k.Stop()
			env, err := k.Start(ctx)
			if err != nil {
				t.Fatalf("starting %s: %v", k.Name(), err)
			}
			for _, rx := range relaxations {
				smb, err := StartSamba(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer smb.VM.Remove()
				if err := smb.Prepare(ctx, env); err != nil {
					t.Fatalf("preparing samba: %v", err)
				}
				r := smb.Run(ctx, env, k.Name(), k.Version(ctx), rx)
				rows = append(rows, r)
				tag := strings.NewReplacer("/", "_", " ", "_").Replace(k.Name()) + "-" + rx.Name
				_ = os.WriteFile(filepath.Join(outDir, tag+"-smbd-log10.txt"), []byte(smb.FullLog(ctx)), 0o600)
				if rx.Role == "" {
					// Fixtures for the offline tests: the real ccache of the run
					// and the keytab that decrypts its service ticket.
					_ = os.WriteFile(filepath.Join(outDir, tag+".ccache"), r.Ccache, 0o600)
					_ = os.WriteFile(filepath.Join(outDir, tag+".keytab"), r.Keytab, 0o600)
				}
				t.Logf("%s [%s]: TGT=%v PAC=%v ad-types=%v smb-ok=%v code=%d err=%q", k.Name(), rx.Name, r.TGT, r.PAC, r.ADTypes, r.SmbOK, r.SmbCode, r.Err)
				t.Logf("smbclient: %s", r.SmbOutput)
				for _, l := range r.Evidence {
					t.Logf("  log: %s", l)
				}
			}
		})
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "matrix.json"), b, 0o600)
	_ = os.WriteFile(filepath.Join(outDir, "matrix.md"), []byte(Table(rows)), 0o600)
	t.Logf("results in %s", outDir)
}

// Table renders rows as the Markdown table of the findings.
func Table(rows []Result) string {
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	var b strings.Builder
	b.WriteString("| KDC | version | PAC in service ticket | ticket enc | Samba accepts | Samba relaxation |\n|---|---|---|---|---|---|\n")
	for _, r := range rows {
		acc := yn(r.SmbOK)
		if r.Err != "" {
			acc = "error: " + r.Err
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r.KDC, r.KDCVersion, yn(r.PAC), r.TicketEnc, acc, r.Relaxation)
	}
	return b.String()
}
