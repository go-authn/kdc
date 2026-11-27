package kdc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc/internal/pac"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// PAC configures the Privilege Attribute Certificate ([MS-PAC]) that service
// tickets can carry. The zero Config.PAC (nil) issues none, which is what a
// standalone Samba needs: it refuses a ticket whose PAC holds LOGON_INFO.
type PAC struct {
	// DomainSID is the domain's SID, S-1-5-21-a-b-c, generated once with
	// [NewDomainSID] and then kept: changing it changes every user's SID.
	DomainSID string

	// Services lists the service principals ("cifs/host.example.org") whose
	// tickets carry a PAC. Any other service gets none.
	Services []string

	// NetBIOSDomain is LogonDomainName; empty, the realm's first label.
	NetBIOSDomain string
}

// NewDomainSID returns a random domain SID, S-1-5-21-a-b-c.
func NewDomainSID() (string, error) {
	var b [12]byte
	if _, err := randRead(b[:]); err != nil {
		return "", err
	}
	v := func(i int) uint32 { return uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3]) }
	return fmt.Sprintf("S-1-5-21-%d-%d-%d", v(0), v(4), v(8)), nil
}

// Errors of PAC configuration and issuance.
var (
	// ErrBadDomainSID reports a PAC.DomainSID that is not S-1-5-21-a-b-c.
	ErrBadDomainSID = errors.New("kdc: PAC.DomainSID is not S-1-5-21-a-b-c")
	// errNoNumber is a person (or the service's client) with no uidNumber: it
	// gets no PAC, and a service that requires one gets no ticket.
	errNoNumber = errors.New("the principal has no uidNumber: no PAC can be issued")
	// errRIDClash is a number two names hold.
	errRIDClash = errors.New("two accounts share one uidNumber or gidNumber")
)

// The calls whose failure no input can provoke, as variables so that a test
// can make each one fail and show the failure is reported, not swallowed.
var (
	randRead    = rand.Read
	getEtype    = crypto.GetEtype
	genKey      = types.GenerateEncryptionKey
	marshalASN1 = asn1.Marshal
	encryptWith = crypto.GetEncryptedData
)

// maxPACGroups is the cap on groups in a PAC (the user's decision D8).
const maxPACGroups = 256

type pacState struct {
	domain   pac.SID
	netbios  string
	dns      string
	services map[string]bool
	rids     ridTable
}

func (c *Config) checkPAC() error {
	if c.PAC == nil {
		return nil
	}
	sid, err := pac.ParseSID(c.PAC.DomainSID)
	if err != nil || sid.Authority != 5 || len(sid.Sub) != 4 || sid.Sub[0] != 21 {
		return fmt.Errorf("%w: %q", ErrBadDomainSID, c.PAC.DomainSID)
	}
	return nil
}

func (s *Server) pacState() *pacState {
	c := s.cfg.PAC
	if c == nil {
		return nil
	}
	s.pacOnce.Do(func() {
		sid, _ := pac.ParseSID(c.DomainSID)
		nb := c.NetBIOSDomain
		if nb == "" {
			nb = strings.ToUpper(strings.SplitN(s.cfg.Realm, ".", 2)[0])
		}
		st := &pacState{domain: sid, netbios: nb, dns: strings.ToLower(s.cfg.Realm), services: map[string]bool{}}
		for _, p := range c.Services {
			st.services[p] = true
		}
		s.pacSt = st
	})
	return s.pacSt
}

// wantsPAC says whether tickets to sname carry a PAC.
func (s *Server) wantsPAC(sname types.PrincipalName) bool {
	st := s.pacState()
	return st != nil && st.services[principalName(sname)]
}

// ridTable checks that numbers are unique (D2: a RID is the uidNumber or
// gidNumber itself, so two accounts with one number would share a SID).
type ridTable struct {
	mu     sync.Mutex
	at     time.Time
	users  map[uint32]string
	groups map[uint32]string
}

const ridTTL = time.Minute

func attrNumber(a directory.Attributes, name string) (uint32, bool) {
	v := a.Get(name)
	if len(v) != 1 {
		return 0, false
	}
	n, err := strconv.ParseUint(v[0], 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

func (s *Server) refreshRIDs(t *ridTable) error {
	users := map[uint32]string{}
	groups := map[uint32]string{}
	ids, err := s.cfg.People.Identities()
	if err != nil {
		return fmt.Errorf("%w: %w", errDirectoryDown, err)
	}
	for _, id := range ids {
		if n, ok := attrNumber(id.Attributes(), "uidNumber"); ok {
			if o, dup := users[n]; dup && o != id.Name() {
				return fmt.Errorf("%w: %d (%s, %s)", errRIDClash, n, o, id.Name())
			}
			users[n] = id.Name()
		}
	}
	if ga, ok := s.cfg.People.(directory.GroupAttributer); ok {
		if gl, ok := s.cfg.People.(directory.GroupLister); ok {
			names, err := gl.GroupNames()
			if err != nil {
				return fmt.Errorf("%w: %w", errDirectoryDown, err)
			}
			for _, g := range names {
				at, err := ga.GroupAttributes(g)
				if err != nil {
					continue
				}
				if n, ok := attrNumber(at, "gidNumber"); ok {
					if o, dup := groups[n]; dup && o != g {
						return fmt.Errorf("%w: %d (%s, %s)", errRIDClash, n, o, g)
					}
					groups[n] = g
				}
			}
		}
	}
	t.users, t.groups, t.at = users, groups, now()
	return nil
}

// checkRID refuses a number another account holds.
func (s *Server) checkRID(t *ridTable, user string, uid uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.users == nil || now().Sub(t.at) > ridTTL {
		if err := s.refreshRIDs(t); err != nil {
			return err
		}
	}
	if o := t.users[uid]; o != "" && o != user {
		return fmt.Errorf("%w: %d (%s, %s)", errRIDClash, uid, o, user)
	}
	return nil
}

// logonInfo maps a directory identity to KERB_VALIDATION_INFO.
func (s *Server) logonInfo(st *pacState, id *directory.Identity, authTime time.Time) (*pac.LogonInfo, pac.SID, error) {
	uid, ok := attrNumber(id.Attributes(), "uidNumber")
	if !ok {
		return nil, pac.SID{}, errNoNumber
	}
	if err := s.checkRID(&st.rids, id.Name(), uid); err != nil {
		return nil, pac.SID{}, err
	}
	primary := uint32(513) // Domain Users
	if g, ok := attrNumber(id.Attributes(), "gidNumber"); ok {
		primary = g
	}
	li := &pac.LogonInfo{
		LogonTime:   pac.FileTime(authTime),
		LogoffTime:  pac.FileTimeNever,
		KickOffTime: pac.FileTimeNever, PasswordMustChange: pac.FileTimeNever,
		PasswordCanChange: pac.FileTimeNever,
		EffectiveName:     id.Name(), UserID: uid, PrimaryGroupID: primary,
		LogonDomainName: st.netbios, LogonDomainID: st.domain,
		UserAccountControl: 0x10, // USER_NORMAL_ACCOUNT
	}
	ga, _ := s.cfg.People.(directory.GroupAttributer)
	seen := map[uint32]bool{primary: true}
	li.Groups = append(li.Groups, pac.Group{RID: primary, Attrs: pac.GroupAttrs})
	if ga != nil {
		for _, g := range id.Groups() {
			if len(li.Groups) >= maxPACGroups {
				break
			}
			at, err := ga.GroupAttributes(g)
			if err != nil {
				continue
			}
			n, ok := attrNumber(at, "gidNumber")
			if !ok || seen[n] { // D9: no gidNumber, no entry
				continue
			}
			seen[n] = true
			li.Groups = append(li.Groups, pac.Group{RID: n, Attrs: pac.GroupAttrs})
		}
	}
	if len(li.ExtraSIDs) > 0 {
		li.UserFlags |= 0x20 // LOGON_EXTRA_SIDS ([MS-PAC] 2.5): only with ExtraSids
	}
	return li, st.domain.WithRID(uid), nil
}

// newTicket is messages.NewTicket with authorization data: that function
// takes none. extra is the PAC builder, given the EncTicketPart bytes with the
// PAC replaced by one zero byte (what the ticket signature covers).
func (s *Server) newTicket(cname types.PrincipalName, sname types.PrincipalName, tflags asn1.BitString,
	kvno int, authTime, start, end time.Time, build func(zeroed []byte, serverKey, kdcKey types.EncryptionKey) ([]byte, error)) (messages.Ticket, types.EncryptionKey, error) {

	et, err := getEtype(defaultEtype)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	session, err := genKey(et)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	skey, _, err := s.cfg.Services.GetEncryptionKey(sname, s.cfg.Realm, kvno, defaultEtype)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	kdcKey, _, err := s.cfg.Services.GetEncryptionKey(
		types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", s.cfg.Realm}},
		s.cfg.Realm, 0, defaultEtype)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	etp := messages.EncTicketPart{
		Flags: tflags, Key: session, CRealm: s.cfg.Realm, CName: cname,
		AuthTime: authTime, StartTime: start, EndTime: end,
	}
	marshal := func(pacBytes []byte) ([]byte, error) {
		inner, err := marshalASN1(types.AuthorizationData{{ADType: adtype.ADWin2KPAC, ADData: pacBytes}})
		if err != nil {
			return nil, err
		}
		etp.AuthorizationData = types.AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: inner}}
		b, err := marshalASN1(etp)
		if err != nil {
			return nil, err
		}
		return asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart), nil
	}
	zeroed, err := marshal([]byte{0})
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	p, err := build(zeroed, skey, kdcKey)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	b, err := marshal(p)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	ed, err := encryptWith(b, skey, keyusage.KDC_REP_TICKET, kvno)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	return messages.Ticket{TktVNO: iana.PVNO, Realm: s.cfg.Realm, SName: sname, EncPart: ed}, session, nil
}

// pacTicket issues a service ticket carrying a PAC for client.
func (s *Server) pacTicket(client types.PrincipalName, sname types.PrincipalName, tflags asn1.BitString,
	kvno int, authTime, start, end time.Time) (messages.Ticket, types.EncryptionKey, error) {

	st := s.pacState()
	id, err := s.lookup(client)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	authSec := authTime.Truncate(time.Second) // MIT compares CLIENT_INFO's authtime exactly
	li, usid, err := s.logonInfo(st, id, authSec)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	return s.newTicket(client, sname, tflags, kvno, authSec, start, end,
		func(zeroed []byte, serverKey, kdcKey types.EncryptionKey) ([]byte, error) {
			return pac.Build(&pac.Input{
				Logon: li, ClientName: id.Name(), AuthTime: authSec,
				UPN: id.Name() + "@" + s.cfg.Realm, DNSDomain: s.cfg.Realm, SamName: id.Name(),
				UserSID: usid, RequestorSID: usid,
				ServiceTicket: true, TicketBytes: zeroed,
			}, serverKey, kdcKey)
		})
}
