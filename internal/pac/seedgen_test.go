package pac

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWriteSeedCorpus writes the committed fuzz seeds when PAC_WRITE_SEEDS=1
// (a valid PAC and LOGON_INFO, each truncated and with one flipped byte per
// 16), so a fuzz run starts from structure instead of from nothing.
func TestWriteSeedCorpus(t *testing.T) {
	if os.Getenv("PAC_WRITE_SEEDS") != "1" {
		t.Skip("PAC_WRITE_SEEDS is not 1")
	}
	logon, err := sampleLogon(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	pb, err := build(&Input{Logon: sampleLogon(t), ClientName: "a", AuthTime: time.Unix(5, 0),
		UserSID: mustSID(t, "S-1-5-21-1-2-3-4"), RequestorSID: mustSID(t, "S-1-5-21-1-2-3-4")}, key(1), key(2))
	if err != nil {
		t.Fatal(err)
	}
	write := func(target string, base []byte) {
		dir := filepath.Join("testdata", "fuzz", target)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		n := 0
		put := func(b []byte) {
			n++
			body := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", b)
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("seed%03d", n)), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		put(base)
		for _, cut := range []int{0, 1, 7, 8, 24, len(base) / 2, len(base) - 1} {
			put(base[:cut])
		}
		for i := 0; i < len(base); i += 16 {
			c := append([]byte(nil), base...)
			c[i] ^= 0xff
			put(c)
		}
	}
	write("FuzzLogonInfo", logon)
	write("FuzzPACVerify", pb)
}
