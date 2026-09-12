package kdc

import (
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
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
func (s *Server) serveTGS(req *messages.TGSReq) []byte {
	sname := req.ReqBody.SName

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
	tgtKey, _, err := s.cfg.Services.GetEncryptionKey(ap.Ticket.SName, ap.Ticket.Realm, 0, defaultEtype)
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
	if d := now().Sub(ap.Authenticator.CTime); d > s.cfg.skew() || d < -s.cfg.skew() {
		return s.krbErr(sname, errorcode.KRB_AP_ERR_SKEW, errClockSkew.Error(), nil)
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
	rep, err := s.issue(req.ReqBody, name[0], sname, session, keyusage.TGS_REP_ENCPART_SESSION_KEY, msgtype.KRB_TGS_REP)
	if err != nil {
		return s.krbErr(sname, errorcode.KDC_ERR_SVC_UNAVAILABLE, err.Error(), nil)
	}
	return rep
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
