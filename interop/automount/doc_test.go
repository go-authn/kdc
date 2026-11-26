package automount

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
)

// docFuncs are the template's functions: the SAME renderers the harness
// installed from, and the results of the run, so a configuration quoted in the
// guide is the one that passed.
func docFuncs(results []CaseResult) template.FuncMap {
	find := func(id, kdc string) *CaseResult {
		for i := range results {
			if results[i].ID == id && results[i].KDC == kdc {
				return &results[i]
			}
		}
		return nil
	}
	fence := func(s string) string { return "```\n" + strings.TrimRight(s, "\n") + "\n```\n" }
	return template.FuncMap{
		"fence":      fence,
		"pkgs":       func() string { return HostPackages },
		"nosync":     func() string { return strings.Replace(KRB5Conf(), "rdns = false", "rdns = false\n  kdc_timesync = 0", 1) },
		"hosts":      func(kdcIP string) string { return HostsFile(kdcIP) },
		"krb5":       KRB5Conf,
		"mitkdc":     MITKDCConf,
		"heimdal":    HeimdalKRB5Conf,
		"smb":        SmbConf,
		"usermap":    func() string { return UserMap(false) },
		"usermapq":   func() string { return UserMap(true) },
		"spnego":     func() string { return SpnegoConf("") },
		"fstab":      FstabLine,
		"automaster": AutofsMaster,
		"automap":    AutofsMap,
		"renewsvc":   RenewService,
		"renewtimer": func() string { return RenewTimer("30min") },
		"networkd":   NetworkdFile,
		"idmap":      func() string { return LXCIdmap },
		"mitadd":     func(n string) string { return MIT().AddScript(n, "") },
		"heimdaladd": func(n string) string { return Heimdal().AddScript(n, "") },
		"mitkt":      func(f, n string) string { return MIT().KeytabScript(f, n) },
		"heimdalkt":  func(f, n string) string { return Heimdal().KeytabScript(f, n) },
		"cell": func(id, kdc string) string {
			c := find(id, kdc)
			switch {
			case c == nil:
				return "non testé"
			case c.Pass:
				return "PASS"
			}
			return "FAIL"
		},
		"title": func(id string) string {
			for _, c := range results {
				if c.ID == id {
					return c.Title
				}
			}
			return id
		},
		"checks": func(id, kdc string) string {
			c := find(id, kdc)
			if c == nil {
				return ""
			}
			var b strings.Builder
			for _, k := range c.Checks {
				mark := "PASS"
				if !k.OK {
					mark = "FAIL"
				}
				fmt.Fprintf(&b, "- %s : %s\n", mark, k.What)
			}
			return b.String()
		},
		// evid is the evidence of a case whose title starts with prefix.
		"evid": func(id, kdc, prefix string) string {
			c := find(id, kdc)
			if c == nil {
				return ""
			}
			for _, e := range c.Ev {
				if strings.HasPrefix(e.Title, prefix) {
					ls := strings.Split(e.Text, "\n")
					if len(ls) > 30 {
						ls = append(ls[:30], "[...]")
					}
					return fence("# " + e.Title + "\n" + strings.Join(ls, "\n"))
				}
			}
			return "(no evidence titled " + prefix + ")\n"
		},
	}
}

// RenderDoc renders the guide template with the results.
func RenderDoc(tmpl string, results []CaseResult) (string, error) {
	t, err := template.New("guide").Funcs(docFuncs(results)).Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Execute(&b, nil); err != nil {
		return "", err
	}
	return b.String(), nil
}

func TestRenderDoc(t *testing.T) {
	rs := []CaseResult{
		{ID: "A1", KDC: "mit", Title: "t", Pass: true, Checks: []Check{{"x", true}}, Ev: []Ev{{"findmnt", "a\nb"}}},
		{ID: "A1", KDC: "heimdal", Title: "t", Checks: []Check{{"y", false}}},
	}
	got, err := RenderDoc(`{{cell "A1" "mit"}} {{cell "A1" "heimdal"}} {{cell "Z" "mit"}} {{title "A1"}} {{title "Q"}}
{{checks "A1" "heimdal"}}{{checks "Z" "mit"}}{{evid "A1" "mit" "find"}}{{evid "A1" "mit" "no"}}{{evid "Z" "mit" "x"}}{{spnego}}`, rs)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"PASS FAIL non testé t Q", "- FAIL : y", "# findmnt\na\nb", "no evidence titled no", "cifs.upcall --keytab"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q missing from %q", w, got)
		}
	}
	if _, err := RenderDoc("{{", nil); err == nil {
		t.Error("bad template accepted")
	}
	if _, err := RenderDoc("{{cell 1 2}}", nil); err == nil {
		t.Error("bad call accepted")
	}
}

// TestDoc renders doc/guide-fr.md from doc/guide-fr.md.tmpl and matrix.json.
func TestDoc(t *testing.T) {
	if os.Getenv("AUTOMOUNT_DOC") != "1" {
		t.Skip("set AUTOMOUNT_DOC=1 to render the guide from a matrix run")
	}
	b, err := os.ReadFile(filepath.Join(outDir(t), "matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rs []CaseResult
	if err := json.Unmarshal(b, &rs); err != nil {
		t.Fatal(err)
	}
	tmpl, err := os.ReadFile("doc/guide-fr.md.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderDoc(string(tmpl), rs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("doc/guide-fr.md", []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
}
