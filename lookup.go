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
	// errNeverValid is a ticket whose end would come before its start.
	errNeverValid = errors.New("the ticket asked for would end before it starts")
)

// ErrNotAPerson reports a principal that is not a single name — a service
// like nfs/host asking for a TGT of its own. Services authenticate from a
// keytab, not from this directory.
var ErrNotAPerson = errors.New("kdc: not a user principal")

// errDirectoryDown is a directory that could not be read. It is an outage, not
// an absent person, and is answered KDC_ERR_SVC_UNAVAILABLE so that a client
// retries instead of concluding the principal does not exist.
var errDirectoryDown = errors.New("kdc: reading the directory")

// Finder is a [directory.Source] that can find one person by name without
// handing over everybody. [Config.People] may implement it; when it does,
// [Server] asks it instead of walking [directory.Source.Identities].
//
// Find reports the identity whose Name is EXACTLY name — a Kerberos principal
// is case-sensitive (RFC 4120 6.2), so a source indexed by a folded name must
// compare the original — found false when there is none, and an error when the
// source cannot be read, which is answered KDC_ERR_SVC_UNAVAILABLE.
//
// It exists because the walk is the cost of a request: with 10,000 people it
// was half of an AS-REQ's CPU (go-authn/kdc#31), and it grows with the
// directory. The source owns the index, so it is as fresh as the source is.
type Finder interface {
	Find(name string) (id *directory.Identity, found bool, err error)
}

// lookup finds a person by their Kerberos principal name.
//
// Without a [Finder] it walks the directory rather than indexing it: a Source
// publishes identities and nothing else, and building a map here would be a
// second copy of the truth that goes stale the moment somebody's password
// changes.
func (s *Server) lookup(p types.PrincipalName) (*directory.Identity, error) {
	if len(p.NameString) != 1 {
		return nil, ErrNotAPerson
	}
	want := p.NameString[0]
	if f, ok := s.cfg.People.(Finder); ok {
		id, found, err := f.Find(want)
		switch {
		case err != nil:
			return nil, fmt.Errorf("%w: %w", errDirectoryDown, err)
		case !found || id == nil || id.Name() != want:
			return nil, fmt.Errorf("kdc: no principal %q", want)
		}
		return id, nil
	}
	ids, err := s.cfg.People.Identities()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errDirectoryDown, err)
	}
	for _, id := range ids {
		if id.Name() == want {
			return id, nil
		}
	}
	return nil, fmt.Errorf("kdc: no principal %q", want)
}
