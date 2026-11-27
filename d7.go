package kdc

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/kdc/internal/cammac"
	"github.com/go-authn/kdc/internal/pac"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// D7: how a person logged in, carried from the TGT to the PAC.
//
// With [Config.PAC] set, every ticket-granting ticket this KDC issues (AS,
// Mint, and the TGS when it reissues one) holds a signed container
// (internal/cammac) saying how the person logged in and which uidNumber they
// had. The TGS verifies it before it issues anything, and turns it into the
// PAC's ExtraSids:
//
//   - S-1-18-1 (AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY) on every PAC, with
//     the D bit ([MS-KILE] 3.3.5.6.4.1: ExtraSids SHOULD hold it and the D bit
//     SHOULD be set; [MS-SFU] 3.2.5.1.2 for the TGS carrying it over);
//   - and, for a TGT a bridge minted, the domain SID with [PAC.MintedRID], so a
//     service can tell a federated or passkey logon from a password one.
//
// S-1-18-2 (service asserted identity) is never written: nothing here is a
// service's assertion. No hardware-authenticator bit is set.
//
// The uidNumber in the container is the CVE-2021-42287 defence: a TGT whose
// name now belongs to another uidNumber (the account was deleted and created
// again) buys nothing.
//
// A TGT issued before the upgrade holds no container. Those are accepted for
// [MaxUnmarkedWindow] after this process started, so that nobody has to log in
// again at the moment of the upgrade, and refused after. They are taken for
// password logons.

// MaxUnmarkedWindow is the longest an unmarked TGT is accepted after the KDC
// started: the longest TGT a Mint can have made ([MaxMintLifetime]), so none
// older than the window can still be alive.
const MaxUnmarkedWindow = MaxMintLifetime

// DefaultMintedRID is the RID of the SID that marks a minted TGT when
// [PAC.MintedRID] is zero. RIDs of users and groups are their uidNumber and
// gidNumber, so this sits above any plausible one; a directory that uses it
// must set another.
const DefaultMintedRID uint32 = 1 << 30

// The login methods a [MintRequest] can name, and the indicator each becomes.
var mintMethods = map[string]string{
	"passkey":   cammac.MethodPasskey,
	"federated": cammac.MethodFederated,
	"machine":   cammac.MethodMachine,
}

// ErrMintBadMethod reports a [MintRequest.Method] that is missing (with a PAC
// configured) or not one of passkey, federated, machine.
var ErrMintBadMethod = errors.New("kdc: mint: method must be one of passkey, federated, machine")

// s1181 is S-1-18-1.
var s1181 = pac.SID{Authority: 18, Sub: []uint32{1}}

func (s *Server) mintedRID() uint32 {
	if s.cfg.PAC != nil && s.cfg.PAC.MintedRID != 0 {
		return s.cfg.PAC.MintedRID
	}
	return DefaultMintedRID
}

func (c *Config) checkD7() error {
	if c.PAC == nil {
		return nil
	}
	if c.PAC.UnmarkedWindow < 0 || c.PAC.UnmarkedWindow > MaxUnmarkedWindow {
		return fmt.Errorf("kdc: PAC.UnmarkedWindow must be within 0 and %s", MaxUnmarkedWindow)
	}
	if c.PAC.MintedRID >= 1<<31 {
		return errors.New("kdc: PAC.MintedRID must be below 2^31")
	}
	return nil
}

// unmarkedUntil is when unmarked TGTs stop being accepted.
func (s *Server) unmarkedUntil() time.Time {
	if s.cfg.PAC.RefuseUnmarked {
		return time.Time{}
	}
	w := s.cfg.PAC.UnmarkedWindow
	if w == 0 {
		w = MaxUnmarkedWindow
	}
	return s.started.Add(w)
}

func (s *Server) krbtgtName() types.PrincipalName {
	return types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", s.cfg.Realm}}
}

// uidOf is the uidNumber an identity holds, zero when none.
func uidOf(id *directory.Identity) uint32 {
	n, _ := attrNumber(id.Attributes(), "uidNumber")
	return n
}

// newTGT makes a ticket-granting ticket carrying the container for claims.
func (s *Server) newTGT(cname types.PrincipalName, tflags asn1.BitString, authTime, start, end time.Time,
	claims cammac.Claims) (messages.Ticket, types.EncryptionKey, error) {

	et, err := getEtype(defaultEtype)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	session, err := genKey(et)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	krbtgt := s.krbtgtName()
	key, kvno, err := s.cfg.Services.GetEncryptionKey(krbtgt, s.cfg.Realm, 0, defaultEtype)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	etp := messages.EncTicketPart{
		Flags: tflags, Key: session, CRealm: s.cfg.Realm, CName: cname,
		AuthTime: authTime, StartTime: start, EndTime: end,
	}
	ad, err := cammac.Seal(etp, claims, key, kvno)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	etp.AuthorizationData = ad
	b, err := marshalASN1(etp)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	ed, err := encryptWith(asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart), key, keyusage.KDC_REP_TICKET, kvno)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	return messages.Ticket{TktVNO: iana.PVNO, Realm: s.cfg.Realm, SName: krbtgt, EncPart: ed}, session, nil
}

// checkMark reads and verifies the container of a TGT the TGS was handed, and
// says whether the TGT may buy anything. A zero code is yes.
func (s *Server) checkMark(tgt *messages.EncTicketPart, key types.EncryptionKey, kvno int,
	id *directory.Identity) (cammac.Claims, int32, string) {

	c, found, err := cammac.Find(*tgt, key, kvno)
	if err != nil {
		s.logf("kdc: a TGT for %s has a marking that does not verify: %v", principalName(tgt.CName), err)
		return cammac.Claims{}, errorcode.KRB_AP_ERR_MODIFIED, "the ticket's authentication marking does not verify"
	}
	if !found {
		if !tgt.StartTime.Before(s.started) || !now().Before(s.unmarkedUntil()) {
			return cammac.Claims{}, errorcode.KDC_ERR_TGT_REVOKED, "the ticket-granting ticket carries no authentication marking: log in again"
		}
		return cammac.Claims{}, 0, ""
	}
	// CVE-2021-42287: the name now belongs to another account.
	if c.UID != uidOf(id) {
		return cammac.Claims{}, errorcode.KDC_ERR_TGT_REVOKED, "the ticket-granting ticket was issued to another account of that name"
	}
	return c, 0, ""
}

// markSIDs adds what a login method says to the PAC: S-1-18-1 on every PAC,
// the minted SID when a bridge vouched, and the D bit with them.
func (s *Server) markSIDs(li *pac.LogonInfo, st *pacState, c cammac.Claims) {
	li.ExtraSIDs = append(li.ExtraSIDs, pac.ExtraSID{SID: s1181, Attrs: pac.GroupAttrs})
	if c.Minted() {
		li.ExtraSIDs = append(li.ExtraSIDs, pac.ExtraSID{SID: st.domain.WithRID(s.mintedRID()), Attrs: pac.GroupAttrs})
	}
	li.UserFlags |= 0x20 // LOGON_EXTRA_SIDS ([MS-PAC] 2.5): ExtraSids is not empty
}
