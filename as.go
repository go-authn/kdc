package kdc

import (
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// serveAS answers an AS-REQ: somebody with a password asking for a TGT.
func (s *Server) serveAS(req *messages.ASReq) []byte {
	sname := req.ReqBody.SName
	id, err := s.lookup(req.ReqBody.CName)
	if err != nil {
		return s.unknownPrincipal(sname)
	}
	key, err := s.cfg.keyFor(id)
	if err != nil {
		// The person exists and this realm cannot derive a key for them —
		// a verifier-only source, most likely. Saying "no key" rather than
		// "no such principal" is the difference between a configuration to
		// fix and a name to check.
		return s.krbErr(sname, errorcode.KDC_ERR_NULL_KEY,
			"this realm holds no Kerberos key for that principal", nil)
	}

	ts := findPA(req.PAData, patype.PA_ENC_TIMESTAMP)
	if ts == nil {
		// Not a refusal: the client is being TOLD how to authenticate, and
		// the salt it must use. kinit reads this and prompts for a password.
		return s.krbErr(sname, errorcode.KDC_ERR_PREAUTH_REQUIRED,
			"pre-authentication required", s.preauthHint())
	}
	if err := s.checkTimestamp(ts, key); err != nil {
		return s.krbErr(sname, errorcode.KDC_ERR_PREAUTH_FAILED, err.Error(), s.preauthHint())
	}

	// The service asked for. An AS-REQ normally asks for krbtgt/REALM, and
	// asking for anything else is how a client gets a service ticket without
	// a TGT — which this realm does not offer.
	if principalName(sname) != "krbtgt/"+s.cfg.Realm {
		return s.krbErr(sname, errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
			"this realm issues only krbtgt tickets from an AS-REQ", nil)
	}

	rep, err := s.issue(req.ReqBody, id.Name(), sname, key, keyusage.AS_REP_ENCPART, msgtype.KRB_AS_REP)
	if err != nil {
		return s.krbErr(sname, errorcode.KDC_ERR_SVC_UNAVAILABLE, err.Error(), nil)
	}
	return rep
}

// preauthHint is the e-data that tells a client HOW to pre-authenticate.
//
// The salt is the load-bearing part. A client that guesses it derives a key
// that decrypts nothing, and the failure is reported as a wrong password —
// so a realm that omits this refuses every correct password without ever
// saying why.
func (s *Server) preauthHint() types.PADataSequence {
	info := types.ETypeInfo2{{EType: defaultEtype}}
	b, err := asn1.Marshal(info)
	if err != nil {
		return nil
	}
	return types.PADataSequence{
		{PADataType: patype.PA_ENC_TIMESTAMP},
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: b},
	}
}

// findPA picks one pre-authentication element out of a request.
func findPA(pa types.PADataSequence, want int32) []byte {
	for _, p := range pa {
		if p.PADataType == want {
			return p.PADataValue
		}
	}
	return nil
}

// checkTimestamp decrypts the client's PA-ENC-TIMESTAMP and checks the clock.
//
// This is the whole of the authentication: only somebody who knows the
// password can produce a timestamp this key decrypts. It is also why a
// verifier-backed directory cannot serve a KDC.
func (s *Server) checkTimestamp(raw []byte, key types.EncryptionKey) error {
	var ed types.EncryptedData
	if err := ed.Unmarshal(raw); err != nil {
		s.logf("the PA-ENC-TIMESTAMP is not an EncryptedData: %v", err)
		return errBadPreauth
	}
	// ⛔ gokrb5 slices a checksum and a confounder off without checking
	// either is there; a short cipher panics. The bytes come from the
	// network, so the check is load-bearing rather than defensive.
	et, err := crypto.GetEtype(ed.EType)
	if err != nil {
		return errBadPreauth
	}
	if len(ed.Cipher) < et.GetConfounderByteSize()+et.GetHMACBitLength()/8 {
		return errBadPreauth
	}
	plain, err := crypto.DecryptEncPart(ed, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP)
	if err != nil {
		s.logf("the timestamp does not decrypt (client etype %d, our key type %d): %v",
			ed.EType, key.KeyType, err)
		return errWrongPassword
	}
	// PA-ENC-TS-ENC is a bare SEQUENCE: unlike most of Kerberos it carries no
	// application tag, and asking for one fails the parse AFTER a successful
	// decryption — which reads as "malformed", not as "my mistake".
	var pt types.PAEncTSEnc
	if _, err := asn1.Unmarshal(plain, &pt); err != nil {
		s.logf("the timestamp decrypted and did not parse: %v", err)
		return errBadPreauth
	}
	if d := now().Sub(pt.PATimestamp); d > s.cfg.skew() || d < -s.cfg.skew() {
		return errClockSkew
	}
	return nil
}

// issue builds a ticket and the reply that carries it.
func (s *Server) issue(body messages.KDCReqBody, cname string, sname types.PrincipalName,
	replyKey types.EncryptionKey, usage uint32, mt int) ([]byte, error) {

	start := now().UTC()
	end := start.Add(s.cfg.lifetime())
	if !body.Till.IsZero() && body.Till.Before(end) {
		// A client may ask for less. Giving it more than it asked for would
		// leave a credential alive past the point its holder expects.
		end = body.Till
	}

	client := types.PrincipalName{NameType: nametypePrincipal, NameString: []string{cname}}

	// The key version is READ from the keytab and stamped on the ticket.
	// Passing zero to NewTicket means "any version" for the lookup AND zero
	// on the wire, and an acceptor holding several versions then has to
	// guess which one sealed it.
	_, kvno, err := s.cfg.Services.GetEncryptionKey(sname, s.cfg.Realm, 0, defaultEtype)
	if err != nil {
		return nil, err
	}
	tkt, sessionKey, err := messages.NewTicket(client, s.cfg.Realm, sname, s.cfg.Realm,
		types.NewKrbFlags(), s.cfg.Services, defaultEtype, kvno, start, start, end, time.Time{})
	if err != nil {
		return nil, err
	}

	enc := messages.EncKDCRepPart{
		Key:      sessionKey,
		Nonce:    body.Nonce,
		AuthTime: start,
		EndTime:  end,
		SRealm:   s.cfg.Realm,
		SName:    sname,
		LastReqs: []messages.LastReq{{LRType: 0, LRValue: start}},
	}
	tag := asnAppTag.EncASRepPart
	if mt == msgtype.KRB_TGS_REP {
		tag = asnAppTag.EncTGSRepPart
	}
	eb, err := asn1.Marshal(enc)
	if err != nil {
		return nil, err
	}
	eb = asn1tools.AddASNAppTag(eb, tag)
	ed, err := crypto.GetEncryptedData(eb, replyKey, usage, 0)
	if err != nil {
		return nil, err
	}

	rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{
		PVNO:    iana.PVNO,
		MsgType: mt,
		CRealm:  s.cfg.Realm,
		CName:   client,
		Ticket:  tkt,
		EncPart: ed,
	}}
	if mt == msgtype.KRB_TGS_REP {
		t := messages.TGSRep(rep)
		return t.Marshal()
	}
	return rep.Marshal()
}
