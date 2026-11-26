package pac

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jcmturner/gokrb5/v8/types"
)

// A refusal that is a guard against a panic (an index past the buffer) must be
// asserted as a refusal: with the guard removed, the panic is turned into an
// error that is not the one expected, so the test FAILS instead of crashing --
// a crash would pass for "caught" without saying what the guard is for.
var errPanicked = errors.New("a runtime error escaped the guard")

func try(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", errPanicked, r)
		}
	}()
	return fn()
}

func unmarshal(b []byte) (l *LogonInfo, err error) {
	err = try(func() (e error) { l, e = UnmarshalLogonInfo(b); return })
	return
}

func parse(b []byte) (p *PAC, err error) {
	err = try(func() (e error) { p, e = Parse(b); return })
	return
}

func verify(p *PAC, srvKey, kdcKey types.EncryptionKey, ticket bool, tb []byte) error {
	return try(func() error { return p.Verify(srvKey, kdcKey, ticket, tb) })
}

func clientInfoOf(p *PAC) (ft int64, name string, err error) {
	err = try(func() (e error) { ft, name, e = p.ClientInfo(); return })
	return
}

func parseBinary(b []byte) (s SID, err error) {
	err = try(func() (e error) { s, e = ParseBinarySID(b); return })
	return
}

func equalSIDs(t *testing.T, a, b SID) (eq bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Equal: a runtime error escaped: %v", r)
		}
	}()
	return a.Equal(b)
}

func build(in *Input, srv, kdc types.EncryptionKey) (b []byte, err error) {
	err = try(func() (e error) { b, e = Build(in, srv, kdc); return })
	return
}

func parseSID(s string) (v SID, err error) {
	err = try(func() (e error) { v, e = ParseSID(s); return })
	return
}

// sigOf is the signature buffer of type typ, or a test failure: a missing
// buffer is reported as one rather than indexed past its end.
func sigOf(t *testing.T, p *PAC, typ uint32) []byte {
	t.Helper()
	b, ok := p.Buffer(typ)
	if !ok || len(b) != 4+checksumLen {
		t.Fatalf("buffer %d: found %v, %d bytes", typ, ok, len(b))
	}
	return b
}
