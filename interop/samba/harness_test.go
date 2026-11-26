// SPDX-License-Identifier: BSD-3-Clause

package samba

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func sambaFiles(t *testing.T) map[string][]byte {
	return map[string][]byte{
		"/tmp/krb5cc_interop": fixture(t, "go-authn_kdc-none.ccache"),
		logPath:               []byte("Unable to find PAC for alice\nnoise\n"),
	}
}

func goEnv(t *testing.T) Env {
	return Env{Realm: "GOAUTHN.TEST", KDC: "k:88", Keytab: fixture(t, "go-authn_kdc-none.keytab")}
}

func TestPrepareRefusals(t *testing.T) {
	e := goEnv(t)
	for _, idMissing := range []bool{false, true} {
		failEachCall(t, fakeDocker{idMissing: idMissing}, func(ctx context.Context) error {
			return Samba{Node{Name: "s"}}.Prepare(ctx, e)
		})
	}
}

func TestRunRefusals(t *testing.T) {
	e := goEnv(t)
	member := Relaxation{Name: "member+winbindd", Role: "member server",
		Setup:   [][]string{{"net", "setdomainsid", PACDomainSID}},
		Daemons: [][]string{{"winbindd", "--foreground", "--no-process-group"}}}
	for _, rx := range []Relaxation{{Name: "none"}, {Name: "member", Role: "member server"}, member} {
		failEachCall(t, fakeDocker{files: sambaFiles(t)}, func(ctx context.Context) error {
			r := Samba{Node{Name: "s"}}.Run(ctx, e, "go", "v", rx)
			if r.Err == "" && (!r.SmbOK || !r.TGT || r.PAC || r.TicketEnc != "Etype (skey, tkt): aes256, aes256") {
				return fmt.Errorf("a clean run read as %+v", r)
			}
			if r.Err == "" {
				return nil
			}
			return fmt.Errorf("%s", r.Err)
		})
	}
}

func TestRunSmbOutcomes(t *testing.T) {
	e := goEnv(t)
	f := &fakeDocker{failAt: -1, files: sambaFiles(t)}
	install(t, f)
	r := Samba{Node{Name: "s"}}.Run(context.Background(), e, "go", "v", Relaxation{Name: "none"})
	if r.Err != "" || !r.SmbOK || r.SmbCode != 0 || !reflect.DeepEqual(r.Evidence, []string{"Unable to find PAC for alice"}) {
		t.Fatalf("%+v", r)
	}
	if string(r.Ccache) == "" || string(r.Keytab) == "" {
		t.Fatal("the evidence of the verdict was not kept")
	}
	// smbclient exiting non-zero is a refusal by Samba, not an error of the harness.
	for i, c := range f.calls {
		if !slices.Contains(c, "smbclient") {
			continue
		}
		f2 := &fakeDocker{failAt: i, files: sambaFiles(t)}
		install(t, f2)
		r = Samba{Node{Name: "s"}}.Run(context.Background(), e, "go", "v", Relaxation{Name: "none"})
		if r.Err != "" || r.SmbOK || r.SmbCode != 1 || !strings.Contains(r.SmbOutput, "exit-") {
			t.Fatalf("a refused smbclient read as %+v", r)
		}
	}
}

func TestRunSmbdNeverAnswers(t *testing.T) {
	f := &fakeDocker{failAt: -1, files: sambaFiles(t), pingFails: true}
	install(t, f)
	r := Samba{Node{Name: "s"}}.Run(context.Background(), goEnv(t), "go", "v", Relaxation{Name: "none"})
	if !strings.Contains(r.Err, "smbd did not come up") {
		t.Fatalf("Err = %q", r.Err)
	}
}

func TestRunRefusesAKeytabThatDoesNotDecode(t *testing.T) {
	f := &fakeDocker{failAt: -1, files: sambaFiles(t)}
	install(t, f)
	e := goEnv(t)
	e.Keytab = []byte("not a keytab")
	r := Samba{Node{Name: "s"}}.Run(context.Background(), e, "go", "v", Relaxation{Name: "none"})
	if !strings.Contains(r.Err, "the service keytab does not decode") {
		t.Fatalf("Err = %q", r.Err)
	}
}

func TestRunRefusesATicketNobodyCanRead(t *testing.T) {
	files := sambaFiles(t)
	files["/tmp/krb5cc_interop"] = []byte("junk")
	f := &fakeDocker{failAt: -1, files: files}
	install(t, f)
	r := Samba{Node{Name: "s"}}.Run(context.Background(), goEnv(t), "go", "v", Relaxation{Name: "none"})
	if !strings.Contains(r.Err, "ccache:") {
		t.Fatalf("Err = %q", r.Err)
	}
}

func TestSmbConf(t *testing.T) {
	s := Samba{}
	base := s.smbConf("R.TEST", Relaxation{Name: "none"})
	for _, want := range []string{"server role = standalone server\n", "security = user\n", "realm = R.TEST\n", "[share]\n  path = /srv/share\n"} {
		if !strings.Contains(base, want) {
			t.Errorf("baseline lacks %q:\n%s", want, base)
		}
	}
	member := s.smbConf("R.TEST", Relaxation{Name: "m", Role: "member server", Line: "extra = 1"})
	if !strings.Contains(member, "server role = member server\n") || strings.Contains(member, "security = user") || !strings.Contains(member, "  extra = 1\n") {
		t.Errorf("member server conf:\n%s", member)
	}
}

func TestKrb5Conf(t *testing.T) {
	c := krb5Conf("R.TEST", "kdc.example:88")
	for _, want := range []string{"default_realm = R.TEST", "kdc = kdc.example:88", "rdns = false", Host + " = R.TEST", ".interop.test = R.TEST"} {
		if !strings.Contains(c, want) {
			t.Errorf("krb5.conf lacks %q:\n%s", want, c)
		}
	}
}

func TestImageName(t *testing.T) {
	if ImageName("mit") != "go-authn-kdc-interop-mit" {
		t.Fatal(ImageName("mit"))
	}
}
