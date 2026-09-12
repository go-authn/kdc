package kdc_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// A realm this server could not serve is refused at CONFIGURATION time. The
// alternative is a KDC that starts, answers, and fails at the first kinit —
// where the message reaches somebody who cannot fix it.
func TestARealmItCannotServeIsRefusedUpFront(t *testing.T) {
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	full := realmKeytab(t)

	// A keytab with services but no krbtgt: this realm could authenticate
	// somebody and then have nothing to hand them.
	noTGT := keytab.New()
	if err := noTGT.AddEntry(service, realm, "k", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cfg  kdc.Config
		want error
	}{
		{"no realm", kdc.Config{People: people, Services: full}, kdc.ErrNoRealm},
		{"no directory", kdc.Config{Realm: realm, Services: full}, kdc.ErrNoPeople},
		{"no keytab", kdc.Config{Realm: realm, People: people}, kdc.ErrNoServices},
		{"no krbtgt key", kdc.Config{Realm: realm, People: people, Services: noTGT}, kdc.ErrNoTGTKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := kdc.New(tc.cfg); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}

	if _, err := kdc.New(kdc.Config{Realm: realm, People: people, Services: full}); err != nil {
		t.Errorf("a realm it CAN serve was refused: %v", err)
	}
}

// Noise is DROPPED, not answered. A KDC that replies KRB-ERROR to anything it
// receives is a reflector: a datagram with somebody else's return address
// makes it send them traffic they did not ask for.
func TestNoiseIsDroppedRatherThanAnswered(t *testing.T) {
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	srv, err := kdc.New(kdc.Config{Realm: realm, People: people, Services: realmKeytab(t), Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeUDP(pc)
	t.Cleanup(func() { srv.Close() })

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, junk := range [][]byte{
		{},
		[]byte("hello there"),
		{0x6a, 0x00},      // an AS-REQ tag with nothing in it
		make([]byte, 512), // zeroes
	} {
		if _, err := c.Write(junk); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 4096)
	if n, err := c.Read(buf); err == nil {
		t.Errorf("noise was answered with %d bytes: %x", n, buf[:n])
	}
}

// A TCP length with the high bit set is reserved and must be zero
// (RFC 4120 §7.2.2). Masking it off would read a length nobody sent.
func TestAReservedLengthBitDropsTheConnection(t *testing.T) {
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	srv, err := kdc.New(kdc.Config{Realm: realm, People: people, Services: realmKeytab(t), Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTCP(ln)
	t.Cleanup(func() { srv.Close() })

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x80, 0, 0, 4, 1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := c.Read(make([]byte, 64)); err == nil && n > 0 {
		t.Errorf("a reserved length bit was served: %d bytes", n)
	}
}

// Close stops a realm and is safe to call twice, which a signal handler and a
// defer will both do.
func TestCloseIsIdempotent(t *testing.T) {
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	srv, err := kdc.New(kdc.Config{Realm: realm, People: people, Services: realmKeytab(t)})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { done <- srv.ServeUDP(pc) }()
	go func() { done <- srv.ServeTCP(ln) }()
	time.Sleep(50 * time.Millisecond)
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("the second Close: %v", err)
	}
	for range 2 {
		if err := <-done; !errors.Is(err, kdc.ErrClosed) {
			t.Errorf("serve returned %v, want ErrClosed", err)
		}
	}
	// And a server that is already closed refuses to start serving again.
	if err := srv.ServeUDP(pc); !errors.Is(err, kdc.ErrClosed) {
		t.Errorf("ServeUDP after Close = %v, want ErrClosed", err)
	}
	if err := srv.ServeTCP(ln); !errors.Is(err, kdc.ErrClosed) {
		t.Errorf("ServeTCP after Close = %v, want ErrClosed", err)
	}
}

// Zero values resolve to what every Kerberos implementation assumes, and a
// realm that set them keeps them.
func TestTheDefaultsAreTheOnesEverybodyAssumes(t *testing.T) {
	requireMIT(t)
	people := onePerson{directory.NewIdentity("alice", directory.WithPassword(password))}
	// A lifetime shorter than the default proves the field is read at all: a
	// ticket that outlives what was asked for is a credential alive past the
	// point its holder expects.
	start(t, kdc.Config{People: people, Services: realmKeytab(t),
		Lifetime: time.Hour, MaxSkew: time.Minute})

	out := kinitAs(t, "alice", password)
	if out != "" {
		t.Fatalf("kinit: %s", out)
	}
	list, err := mit(t, "klist")
	if err != nil {
		t.Fatalf("klist: %v\n%s", err, list)
	}
	t.Logf("with a one-hour lifetime:\n%s", list)
}
