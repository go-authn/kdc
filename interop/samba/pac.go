// SPDX-License-Identifier: BSD-3-Clause

// Package samba is an interoperability harness: it puts a Samba file server,
// configured as a non-AD server, behind three KDCs (go-authn/kdc, MIT krb5kdc,
// Heimdal kdc) and records whether each one's tickets are accepted.
//
// The test that drives it needs virtual machines and is skipped unless
// SAMBA_INTEROP=1; see README.md in this directory.
package samba

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// adWin2KPAC is AD-WIN2K-PAC (MS-KILE 3.3.5.3.1 / [MS-PAC] 2.1): the
// authorization-data type that carries a PAC. gokrb5's adtype package does not
// name it.
const adWin2KPAC int32 = 128

// HasPAC reports whether authorization data carries a PAC, either bare or
// wrapped in AD-IF-RELEVANT (RFC 4120 5.2.6.1), which is where a KDC puts it.
func HasPAC(ad types.AuthorizationData) (bool, error) {
	for _, e := range ad {
		switch e.ADType {
		case adWin2KPAC:
			return true, nil
		case adtype.ADIfRelevant:
			var inner types.AuthorizationData
			if err := inner.Unmarshal(e.ADData); err != nil {
				return false, fmt.Errorf("AD-IF-RELEVANT does not decode: %w", err)
			}
			if ok, err := HasPAC(inner); err != nil || ok {
				return ok, err
			}
		}
	}
	return false, nil
}

// Describe lists the authorization-data types of ad, an AD-IF-RELEVANT shown
// with what it wraps: "1[128]" is a PAC in AD-IF-RELEVANT, "1[]" an empty one.
func Describe(ad types.AuthorizationData) []string {
	var out []string
	for _, e := range ad {
		if e.ADType != adtype.ADIfRelevant {
			out = append(out, fmt.Sprint(e.ADType))
			continue
		}
		var inner types.AuthorizationData
		if err := inner.Unmarshal(e.ADData); err != nil {
			out = append(out, "1[undecodable]")
			continue
		}
		var in []string
		for _, i := range inner {
			in = append(in, fmt.Sprint(i.ADType))
		}
		out = append(out, "1["+strings.Join(in, ",")+"]")
	}
	return out
}

// TicketTypes decrypts the service ticket held in a credential cache with the
// service's keytab and returns the authorization-data types it carries and
// whether one of them is a PAC. The ticket is decoded, never inferred from the
// name of the KDC that issued it.
func TicketTypes(ccache []byte, kt *keytab.Keytab, service string) (adTypes []string, pac bool, err error) {
	// gokrb5 v8.4.4 indexes into the bytes of a ccache without checking their
	// length (CCache.Unmarshal panics on an empty input, found by
	// FuzzTicketTypes), and this is untrusted input: a panic is a refusal.
	defer func() {
		if r := recover(); r != nil {
			adTypes, pac, err = nil, false, fmt.Errorf("ccache: decoder panicked: %v", r)
		}
	}()
	var cc credentials.CCache
	if err = cc.Unmarshal(ccache); err != nil {
		return nil, false, fmt.Errorf("ccache: %w", err)
	}
	for _, c := range cc.Credentials {
		// Skip the TGT and the configuration entries MIT keeps in a cache
		// (krb5_ccache_conf_data/...): only the service's ticket is wanted.
		if strings.Join(c.Server.PrincipalName.NameString, "/") != service {
			continue
		}
		var t messages.Ticket
		if err = t.Unmarshal(c.Ticket); err != nil {
			return nil, false, fmt.Errorf("ticket: %w", err)
		}
		if err = t.DecryptEncPart(kt, nil); err != nil {
			return nil, false, fmt.Errorf("decrypting the ticket for %s with the service keytab: %w", service, err)
		}
		pac, err = HasPAC(t.DecryptedEncPart.AuthorizationData)
		return Describe(t.DecryptedEncPart.AuthorizationData), pac, err
	}
	return nil, false, errors.New("no service ticket in the credential cache")
}
