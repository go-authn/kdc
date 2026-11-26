package kdc

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
)

// RFC 4120 7.2.1: a reply too big for a datagram is answered with
// KRB_ERR_RESPONSE_TOO_BIG, and the same reply is whole over TCP's path.
// The PAC here holds the 256 groups of the cap (D8), which is far over the
// limit.
func TestAReplyTooBigForUDPAnswersResponseTooBig(t *testing.T) {
	kt := testKeytab(t)
	var names []string
	gids := map[string]string{}
	for i := 0; i < 256; i++ {
		n := fmt.Sprintf("g%d", i)
		names = append(names, n)
		gids[n] = fmt.Sprint(5000 + i)
	}
	d := &dirPeople{ids: []*directory.Identity{person(t, "alice", "1001", "1000", names...)}, groupList: names, gids: gids}
	s, err := New(Config{Realm: testRealm, People: d, Services: kt, Logf: t.Logf, AllowPasswordDerivedAS: true,
		PAC: &PAC{DomainSID: testDomainSID, Services: []string{"nfs/localhost"}}})
	if err != nil {
		t.Fatal(err)
	}
	full := tgsOnce(t, s)
	if len(full) <= maxUDPReply {
		t.Fatalf("a PAC of 256 groups is %d bytes, not over the %d of a datagram", len(full), maxUDPReply)
	}
	if li := logonOf(t, full, kt); len(li.Groups) != maxPACGroups {
		t.Fatalf("the full reply holds %d groups", len(li.Groups))
	}
	small := s.udpReply(full)
	if got := krbErrorCode(t, small); got != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
		t.Fatalf("code %d, want RESPONSE_TOO_BIG (52)", got)
	}
	if len(small) > 200 {
		t.Errorf("the refusal is %d bytes: it must not amplify", len(small))
	}
}

// A reply that fits is sent unchanged.
func TestAReplyThatFitsAUDPDatagramIsUnchanged(t *testing.T) {
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	rep := []byte("a reply")
	if got := s.udpReply(rep); string(got) != "a reply" {
		t.Errorf("%q", got)
	}
	rep = make([]byte, maxUDPReply)
	if got := s.udpReply(rep); len(got) != maxUDPReply {
		t.Errorf("a reply of exactly the limit was replaced (%d bytes)", len(got))
	}
	if got := s.udpReply(make([]byte, maxUDPReply+1)); len(got) == maxUDPReply+1 {
		t.Error("a reply one byte over the limit was sent")
	}
}

// Over the real socket, with the limit below any reply.
func TestUDPSocketAnswersResponseTooBig(t *testing.T) {
	defer func(n int) { maxUDPReply = n }(maxUDPReply)
	maxUDPReply = 10
	s := testServer(t, directory.NewIdentity("alice", directory.WithPassword("alicepw")))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeUDP(pc)
	defer s.Close()
	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(asReq(t, "alice", []string{"krbtgt", testRealm}, nil)); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := krbErrorCode(t, buf[:n]); got != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
		t.Errorf("code %d, want 52", got)
	}
}
