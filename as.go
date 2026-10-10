package kdc

import (
	"errors"
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
	// Before the principal is looked up, so the answer says nothing about
	// who exists.
	if !offersDefault(req.ReqBody.EType) {
		return s.etypeNotOffered(sname, req.ReqBody.EType)
	}
	id, err := s.lookup(req.ReqBody.CName)
	if err != nil {
		return s.unknownPrincipal(sname)
	}
	ts := findPA(req.PAData, patype.PA_ENC_TIMESTAMP)
	if ts == nil {
		// ⛔ No key is derived to say this: PBKDF2 costs milliseconds, and a
		// request without pre-authentication comes from anybody, over UDP,
		// from any address it likes. hasKey only asks whether there is a
		// password to derive from.
		if !s.cfg.hasKey(id) {
			return s.nullKey(sname)
		}
		// Not a refusal: the client is being TOLD how to authenticate, and
		// the salt it must use. kinit reads this and prompts for a password.
		return s.krbErr(sname, errorcode.KDC_ERR_PREAUTH_REQUIRED,
			"pre-authentication required", s.preauthHint(s.cfg.saltFor(id)))
	}
	key, err := s.cfg.keyFor(id)
	if err != nil {
		return s.nullKey(sname)
	}
	if err := s.checkTimestamp(ts, key); err != nil {
		return s.krbErr(sname, errorcode.KDC_ERR_PREAUTH_FAILED, err.Error(), s.preauthHint(s.cfg.saltFor(id)))
	}

	// The service asked for. An AS-REQ normally asks for krbtgt/REALM, and
	// asking for anything else is how a client gets a service ticket without
	// a TGT — which this realm does not offer.
	if principalName(sname) != "krbtgt/"+s.cfg.Realm {
		return s.krbErr(sname, errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
			"this realm issues only krbtgt tickets from an AS-REQ", nil)
	}

	rep, err := s.issue(req.ReqBody, id.Name(), sname, key, keyusage.AS_REP_ENCPART, msgtype.KRB_AS_REP, time.Time{})
	if err != nil {
		if errors.Is(err, errNeverValid) {
			return s.krbErr(sname, errorcode.KDC_ERR_NEVER_VALID, err.Error(), nil)
		}
		return s.krbErr(sname, errorcode.KDC_ERR_SVC_UNAVAILABLE, err.Error(), nil)
	}
	return rep
}

// preauthHint is the e-data that tells a client HOW to pre-authenticate.
//
// The salt is the load-bearing part. A client that guesses it derives a key
// that decrypts nothing, and the failure is reported as a wrong password —
// so a realm that omits this refuses every correct password without ever
// saying why. ⛔ It used to be omitted: the field is optional, gokrb5 leaves an
// empty one off the wire, and a client then falls back to the default salt
// (RFC 4120 §4), which happens to be the one keyFor uses -- so nothing failed,
// and the comment above was false until a README audit marshalled the hint.
func (s *Server) preauthHint(salt string) types.PADataSequence {
	info := types.ETypeInfo2{{EType: defaultEtype, Salt: salt}}
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
	replyKey types.EncryptionKey, usage uint32, mt int, notAfter time.Time) ([]byte, error) {

	start := now().UTC()
	end := start.Add(s.cfg.lifetime())
	if !tillUnbounded(body.Till) && body.Till.Before(end) {
		// A client may ask for less. Giving it more than it asked for would
		// leave a credential alive past the point its holder expects.
		end = body.Till
	}
	// And a ticket bought with a TGT ends no later than the TGT: otherwise
	// asking the TGS for krbtgt again extends a credential one lifetime at a
	// time, for ever. notAfter is zero for the AS, which has no TGT.
	if !notAfter.IsZero() && notAfter.Before(end) {
		end = notAfter
	}
	// A ticket that would end before it starts is refused, not issued already
	// expired: RFC 4120 3.1.3 answers it with KDC_ERR_NEVER_VALID.
	if !end.After(start) {
		return nil, errNeverValid
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

// nullKey says the person exists and this realm cannot derive a key for
// them -- a verifier-only source, most likely. Saying "no key" rather than
// "no such principal" is the difference between a configuration to fix and a
// name to check.
func (s *Server) nullKey(sname types.PrincipalName) []byte {
	return s.krbErr(sname, errorcode.KDC_ERR_NULL_KEY,
		"this realm holds no Kerberos key for that principal", nil)
}

// offersDefault reports whether a request lists the one etype this realm
// issues. RFC 4120 §3.1.3: "If the server cannot accommodate any encryption
// type requested by the client, an error message with code
// KDC_ERR_ETYPE_NOSUPP is returned." Issuing etype 18 to a client that did
// not ask for it hands it a reply it cannot decrypt.
func offersDefault(etypes []int32) bool {
	for _, e := range etypes {
		if e == defaultEtype {
			return true
		}
	}
	return false
}

// etypeNotOffered refuses a request that lists no etype this realm issues, and
// records what the client did offer, so an operator can tell a client stuck on
// an old cipher from anything else.
func (s *Server) etypeNotOffered(sname types.PrincipalName, offered []int32) []byte {
	s.logf("kdc: a request offered etypes %v; this realm issues only %d", offered, defaultEtype)
	return s.krbErr(sname, errorcode.KDC_ERR_ETYPE_NOSUPP,
		"this realm issues only aes256-cts-hmac-sha1-96 (etype 18)", nil)
}

// tillUnbounded reports whether a request's till names no end at all.
//
// ⛔ RFC 4120 5.4.1: "if the requested endtime is 19700101000000Z, the
// requested ticket is to have the maximum endtime permitted according to KDC
// policy". That value decodes as the Unix epoch, which is NOT Go's zero time,
// so testing IsZero alone took it for a real end and issued tickets that had
// expired in 1970 -- what Heimdal's kgetcred asks for, and klist then showed
// as >>>Expired<<<.
func tillUnbounded(t time.Time) bool { return t.IsZero() || t.Equal(time.Unix(0, 0)) }
