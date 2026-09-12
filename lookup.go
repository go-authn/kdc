package kdc

import (
	"errors"
	"fmt"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Reasons pre-authentication fails, kept apart because they mean different
// things to whoever has to fix them.
var (
	// errWrongPassword is a timestamp this key does not decrypt.
	errWrongPassword = errors.New("pre-authentication does not decrypt")
	// errBadPreauth is a PA-ENC-TIMESTAMP that is not one.
	errBadPreauth = errors.New("malformed pre-authentication")
	// errClockSkew is a timestamp too far from this clock. It is the one
	// failure that is nobody's mistake, and a client cannot tell it from a
	// wrong password unless the KDC says.
	errClockSkew = errors.New("the client's clock is too far from this one")
)

// ErrNotAPerson reports a principal that is not a single name — a service
// like nfs/host asking for a TGT of its own. Services authenticate from a
// keytab, not from this directory.
var ErrNotAPerson = errors.New("kdc: not a user principal")

// lookup finds a person by their Kerberos principal name.
//
// It walks the directory rather than indexing it: a Source publishes
// identities and nothing else, and building a map here would be a second copy
// of the truth that goes stale the moment somebody's password changes.
func (s *Server) lookup(p types.PrincipalName) (*directory.Identity, error) {
	if len(p.NameString) != 1 {
		return nil, ErrNotAPerson
	}
	want := p.NameString[0]
	ids, err := s.cfg.People.Identities()
	if err != nil {
		return nil, fmt.Errorf("kdc: reading the directory: %w", err)
	}
	for _, id := range ids {
		if id.Name() == want {
			return id, nil
		}
	}
	return nil, fmt.Errorf("kdc: no principal %q", want)
}
