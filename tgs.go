package kdc

import (
	"crypto/md5"
	"crypto/subtle"
	"errors"
	"github.com/go-authn/kdc/internal/cammac"
	"slices"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// serveTGS answers a TGS-REQ: somebody holding a TGT asking for a ticket to a
// service.
//
// No password is involved. What is checked is that the TGT was issued by this
// realm — it decrypts under the krbtgt key — and that whoever presents it
// holds the session key inside, which the authenticator proves.
func (s *Server) serveTGS(req *messages.TGSReq, body []byte) []byte {
	sname := req.ReqBody.SName
	if req.ReqBody.Realm != s.cfg.Realm {
		return s.krbErr(sname, errorcode.KDC_ERR_WRONG_REALM, "this KDC does not serve that realm", nil)
	}
	if !offersDefault(req.ReqBody.EType) {
		return s.etypeNotOffered(sname, req.ReqBody.EType)
	}

	raw := findPA(req.PAData, patype.PA_TGS_REQ)
	if raw == nil {
		return s.krbErr(sname, errorcode.KDC_ERR_PADATA_TYPE_NOSUPP,
			"a TGS-REQ carries its TGT in PA-TGS-REQ", nil)
	}
	var ap messages.APReq
	if err := ap.Unmarshal(raw); err != nil {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_MSG_TYPE, "malformed AP-REQ", nil)
	}

	// ⛔ Both ciphers are measured before anything decrypts them: gokrb5
	// panics on a short one, and these bytes arrive from the network.
	if err := checkCipher(ap.Ticket.EncPart); err != nil {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_MODIFIED, err.Error(), nil)
	}
	if err := checkCipher(ap.EncryptedAuthenticator); err != nil {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_MODIFIED, err.Error(), nil)
	}

	// The TGT must decrypt under this realm's own krbtgt key. That is the
	// whole of "did we issue this".
	//
	// ⛔ Under THAT key, named here -- not the key of whatever SName the
	// ticket carries, which travels in the clear: a ticket for nfs/host,
	// forged by whoever holds that one service's key, decrypted under it
	// and bought a real krbtgt ticket for any name at all. RFC 4120 3.3.2:
	// the ticket in a TGS-REQ is a ticket-granting ticket.
	krbtgt := types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", s.cfg.Realm}}
	if principalName(ap.Ticket.SName) != principalName(krbtgt) || ap.Ticket.Realm != s.cfg.Realm {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_NOT_US, "the ticket presented is not a ticket-granting ticket of this realm", nil)
	}
	tgtKey, _, err := s.cfg.Services.GetEncryptionKey(krbtgt, s.cfg.Realm, 0, defaultEtype)
	if err != nil {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_NOKEY, "this realm has no key for that ticket", nil)
	}
	if err := ap.Ticket.Decrypt(tgtKey); err != nil {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_MODIFIED, "the ticket does not decrypt", nil)
	}

	// And the authenticator must decrypt under the session key INSIDE the
	// ticket. A replayed ticket without it proves nothing: the ticket travels
	// in the clear and anybody can copy it.
	session := ap.Ticket.DecryptedEncPart.Key
	if err := ap.DecryptAuthenticator(session); err != nil {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_BAD_INTEGRITY,
			"the authenticator does not decrypt under the ticket's session key", nil)
	}
	// ⛔ RFC 4120 3.2.3 (a TGS-REQ's PA-TGS-REQ is an AP-REQ): "The name and
	// realm of the client from the ticket are compared against the same fields
	// in the authenticator. If they don't match, the KRB_AP_ERR_BADMATCH error
	// is returned; normally this is caused by a client error or an attempted
	// attack." MIT does it in rd_req_dec.c (krb5_principal_compare of the
	// authenticator's client with the ticket's). Before this the authenticator's
	// name was decrypted and never read.
	if !sameClient(ap.Ticket.DecryptedEncPart.CName, ap.Ticket.DecryptedEncPart.CRealm,
		ap.Authenticator.CName, ap.Authenticator.CRealm) {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_BADMATCH, "the authenticator names another client than the ticket", nil)
	}
	// ⛔ And the authenticator must be about THIS request. RFC 4120 3.3.2:
	// its checksum is over the KDC-REQ-BODY, keyed with the session key.
	// Unchecked, the body was bound to nothing -- the service, the lifetime
	// and the nonce of a request in flight could be rewritten by anybody on
	// the path, and the ticket issued for what they wrote.
	if code, why := checkBodyChecksum(ap.Authenticator.Cksum, session, body); code != 0 {
		return s.krbErr(sname, code, why, nil)
	}
	if d := now().Sub(ap.Authenticator.CTime); d > s.cfg.skew() || d < -s.cfg.skew() {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_SKEW, errClockSkew.Error(), nil)
	}

	// ⛔ The TGT's end is the whole of how a Kerberos credential is revoked:
	// a password change or a removed person stops mattering only when the
	// TGTs already handed out run out. Its times were written by THIS clock,
	// so no skew is allowed them -- the skew above is for the client's.
	tgt := ap.Ticket.DecryptedEncPart
	if !now().Before(tgt.EndTime) {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_TKT_EXPIRED, "the ticket has expired", nil)
	}
	// The start gets the configured skew (MIT's check_tgs does too): the
	// clock can be stepped back after the TGT was written.
	if tgt.StartTime.After(now().Add(s.cfg.skew())) || types.IsFlagSet(&tgt.Flags, flags.Invalid) {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_TKT_NYV, "the ticket is not yet valid", nil)
	}

	// The service asked for must exist in the keytab; otherwise there is no
	// key to seal its ticket with.
	if _, _, err := s.cfg.Services.GetEncryptionKey(sname, s.cfg.Realm, 0, defaultEtype); err != nil {
		return s.krbErr(sname, errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
			"this realm holds no key for that service", nil)
	}

	// The reply is sealed with the TGT's session key, not with any password:
	// the client already proved it holds that key.
	name := ap.Ticket.DecryptedEncPart.CName.NameString
	if len(name) != 1 {
		return s.krbErr(sname, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "not a user principal", nil)
	}
	// And still somebody this realm serves: removed from the directory, a
	// person's TGT buys nothing more (MIT checks the client principal at the
	// TGS too).
	if ap.Ticket.DecryptedEncPart.CRealm != s.cfg.Realm {
		return s.krbErr(sname, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "a client of another realm", nil)
	}
	id, err := s.lookup(ap.Ticket.DecryptedEncPart.CName)
	if err != nil {
		if errors.Is(err, errDirectoryDown) {
			s.logf("kdc: the directory could not be read: %v", err)
			return s.krbErr(sname, errorcode.KDC_ERR_SVC_UNAVAILABLE, "the directory is unavailable", nil)
		}
		return s.krbErr(sname, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "this realm does not know that client", nil)
	}
	// D7: with a PAC configured, the TGT's signed marking is verified before
	// anything is issued, and says how the person logged in.
	var mark cammac.Claims
	if s.pacState() != nil {
		var code int32
		var why string
		if mark, code, why = s.checkMark(&tgt, tgtKey, ap.Ticket.EncPart.KVNO, id); code != 0 {
			return s.krbErr(sname, code, why, nil)
		}
	}
	rep, err := s.issue(req.ReqBody, name[0], sname, session, keyusage.TGS_REP_ENCPART_SESSION_KEY, msgtype.KRB_TGS_REP, tgt.EndTime, &tgt, mark)
	if err != nil {
		if errors.Is(err, errNeverValid) {
			return s.krbErr(sname, errorcode.KDC_ERR_NEVER_VALID, err.Error(), nil)
		}
		if errors.Is(err, errNoNumber) || errors.Is(err, errRIDClash) {
			// The service requires a PAC and this person cannot be given a
			// sound one: refused, never a ticket without it (fail closed).
			s.logf("kdc: no PAC for %s: %v", name[0], err)
			return s.krbErr(sname, errorcode.KDC_ERR_POLICY, "no PAC can be issued for this client", nil)
		}
		return s.krbErr(sname, errorcode.KDC_ERR_SVC_UNAVAILABLE, err.Error(), nil)
	}
	return rep
}

// sameClient compares two client principals as MIT's krb5_principal_compare
// does: the realm and every name component, byte for byte; the name TYPE is
// not compared.
func sameClient(a types.PrincipalName, ar string, b types.PrincipalName, br string) bool {
	return ar == br && slices.Equal(a.NameString, b.NameString)
}

// checkCipher refuses an EncryptedData too short to be one.
//
// gokrb5 slices a checksum off the end and a confounder off the front without
// checking either is there, so a three-byte cipher PANICS — from an
// unauthenticated caller, before any key is checked. A fix is submitted
// upstream (jcmturner/gokrb5#580); this stays until it is released.
func checkCipher(ed types.EncryptedData) error {
	et, err := crypto.GetEtype(ed.EType)
	if err != nil {
		return errBadPreauth
	}
	if len(ed.Cipher) < et.GetConfounderByteSize()+et.GetHMACBitLength()/8 {
		return errBadPreauth
	}
	return nil
}

// checkBodyChecksum says whether an authenticator's checksum is over this
// request body, under this session key. Zero is yes; otherwise the code and
// the reason to refuse with.
//
// Two types are accepted. The session key's own keyed checksum, the type a
// client gets by asking for "the default for this key" (RFC 3961 4: every
// enctype names a mandatory checksum; MIT's and Heimdal's clients use it), and
// RSA-MD5 (cksumtype 7), which Windows sends (MS-KILE).
//
// Why RSA-MD5 is acceptable HERE and nowhere else. RFC 4120 3.3.2 (the KDC
// "MUST" reject a checksum "not collision-proof", KRB_AP_ERR_INAPP_CKSUM) and
// 5.2.7.1 ("MUST be collision-proof") do not ask for it to be keyed.
// RFC 3961 6.1 allows unkeyed checksums "preferably as part of an encrypted
// message", with this very case as its footnote [6]: "in MIT's implementation
// of [Kerb1510], the rsa-md5 unkeyed checksum of application data may be
// included in an authenticator encrypted in a service's key"; 6.1.1 gives
// rsa-md5 (type 7) "associated cryptosystem: any". MIT krb5 enforces exactly
// the RFC 4120 rule: kdc_util.c comp_cksum refuses a type
// that fails krb5_c_is_coll_proof_cksum, and then verifies with
// krb5_c_verify_checksum under the TGT session key; its table
// (lib/crypto/krb/cksumtypes.c) lists RSA-MD5 as CKSUM_UNKEYED and not as
// CKSUM_NOT_COLL_PROOF, so MIT accepts it, as it does the other unkeyed
// hashes. The exposure of an unkeyed checksum is that a path attacker can
// recompute it over a body they rewrote; but here it sits INSIDE the
// authenticator, which is encrypted under the TGT session key with an
// integrity-protected enctype (every enctype this KDC issues carries an HMAC
// over its plaintext), and we decrypted it before arriving here. Whoever
// can rewrite the body AND re-seal the authenticator already holds the
// session key. What remains is a second preimage on MD5 against a body the
// attacker did not choose, which is not known to be feasible, and the
// authenticator is also bound by the replay cache.
//
// Deliberately narrower than MIT: CRC32, RSA-MD4 and SHA-1 (which MIT also
// lets through) stay refused, no client of ours sends them, and CRC32 is not
// collision-proof at all.
func checkBodyChecksum(c types.Checksum, session types.EncryptionKey, body []byte) (int32, string) {
	et, err := crypto.GetEtype(session.KeyType)
	if err != nil {
		return errorcode.KRB_AP_ERR_INAPP_CKSUM, "the session key's type names no checksum"
	}
	if len(c.Checksum) == 0 {
		return errorcode.KRB_AP_ERR_INAPP_CKSUM, "the authenticator carries no checksum over the request"
	}
	if c.CksumType == chksumtype.RSA_MD5 {
		// Windows' form (MS-KILE; observed with a Windows 11 client against
		// this KDC, go-authn/kdc#36). See the doc comment: this is MIT's
		// rule, narrowed to the one unkeyed type a client sends.
		sum := md5.Sum(body) //nolint:gosec // RFC 4120 type 7; the authenticator is sealed, see above
		if len(body) == 0 || subtle.ConstantTimeCompare(sum[:], c.Checksum) != 1 {
			return errorcode.KRB_AP_ERR_MODIFIED, "the authenticator's checksum is not over this request"
		}
		return 0, ""
	}
	if c.CksumType != et.GetHashID() {
		return errorcode.KRB_AP_ERR_INAPP_CKSUM, "the authenticator's checksum is neither the session key's keyed checksum nor RSA-MD5"
	}
	if len(body) == 0 || !et.VerifyChecksum(session.KeyValue, body, c.Checksum, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM) {
		return errorcode.KRB_AP_ERR_MODIFIED, "the authenticator's checksum is not over this request"
	}
	return 0, ""
}
