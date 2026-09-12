package kdc

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/rfc3962"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Config describes one realm.
type Config struct {
	// Realm is the realm name, conventionally the DNS domain in capitals.
	Realm string

	// People is where users come from. It must publish passwords; see the
	// package comment for why a verifier cannot serve Kerberos.
	People directory.Source

	// Services holds the keys for service principals, including the
	// krbtgt/REALM@REALM this KDC issues its own tickets under. It is the
	// same file a service like an NFS server reads, which is the point: one
	// keytab, two readers, no third place for a key to drift.
	Services *keytab.Keytab

	// Lifetime caps a ticket. Zero means ten hours, which is MIT's default.
	Lifetime time.Duration

	// MaxSkew is how far a client's clock may be from this one. Zero means
	// five minutes, which is what every Kerberos implementation assumes.
	MaxSkew time.Duration

	// Logf, when set, is told why a request was refused.
	//
	// It exists because the protocol cannot say: a client is given an error
	// CODE, and "pre-authentication failed" covers a wrong password, a wrong
	// salt, a clock an hour out and a malformed message. Only this side can
	// tell them apart, and only to an operator.
	//
	// ⛔ It is never given a password, a key, or a decrypted anything.
	Logf func(format string, args ...any)
}

// Errors a configuration can have.
var (
	// ErrNoRealm reports a configuration with no realm name.
	ErrNoRealm = errors.New("kdc: no realm")
	// ErrNoPeople reports one with nowhere to look up users.
	ErrNoPeople = errors.New("kdc: no directory")
	// ErrNoServices reports one with no keytab, which means no krbtgt key
	// and therefore nothing to sign a TGT with.
	ErrNoServices = errors.New("kdc: no keytab")
	// ErrNoTGTKey reports a keytab without krbtgt/REALM@REALM. A KDC without
	// it can authenticate somebody and then have nothing to hand them.
	ErrNoTGTKey = errors.New("kdc: the keytab has no krbtgt key for this realm")
)

func (c *Config) check() error {
	switch {
	case c.Realm == "":
		return ErrNoRealm
	case c.People == nil:
		return ErrNoPeople
	case c.Services == nil:
		return ErrNoServices
	}
	if _, _, err := c.Services.GetEncryptionKey(
		types.PrincipalName{NameType: nametypeSrvInst, NameString: []string{"krbtgt", c.Realm}},
		c.Realm, 0, defaultEtype); err != nil {
		return fmt.Errorf("%w: %w", ErrNoTGTKey, err)
	}
	return nil
}

// Principal name types (RFC 4120 §6.2).
const (
	nametypePrincipal = 1
	nametypeSrvInst   = 2
)

// defaultEtype is what tickets and keys are made with. aes256-cts-hmac-sha1-96
// is what every Kerberos implementation in use agrees on; the weaker types a
// client may offer are not issued even when asked for.
const defaultEtype int32 = 18

// lifetime and skew resolve the zero values.
func (c *Config) lifetime() time.Duration {
	if c.Lifetime <= 0 {
		return 10 * time.Hour
	}
	return c.Lifetime
}

func (c *Config) skew() time.Duration {
	if c.MaxSkew <= 0 {
		return 5 * time.Minute
	}
	return c.MaxSkew
}

// keyFor derives a person's long-term key.
//
// The salt is the realm followed by the principal name with no separator,
// which is what RFC 4120 §4 specifies and what every client computes before it
// encrypts its timestamp. Getting it wrong produces a KDC that refuses every
// correct password, and says nothing about why.
func (c *Config) keyFor(id *directory.Identity) (types.EncryptionKey, error) {
	salt := c.Realm + id.Name()
	raw, err := id.KerberosKey(func(password string) ([]byte, error) {
		et, err := crypto.GetEtype(defaultEtype)
		if err != nil {
			return nil, err
		}
		// 4096 is the iteration count RFC 3962 §4 fixes when a realm publishes
		// no s2kparams, and this one does not. gokrb5's StringToKey refuses an
		// empty s2kparams outright rather than applying the default, which
		// surfaces as KDC_ERR_NULL_KEY — a message about the key, from a
		// failure about a parameter.
		return rfc3962.StringToKeyIter(password, salt, 4096, et)
	})
	if err != nil {
		return types.EncryptionKey{}, err
	}
	return types.EncryptionKey{KeyType: defaultEtype, KeyValue: raw}, nil
}

// principalName renders a PrincipalName the way a realm writes it.
func principalName(p types.PrincipalName) string { return strings.Join(p.NameString, "/") }
