package kdc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	// krbtgt/REALM@REALM this KDC issues its own tickets under.
	//
	// ⛔ It is the KDC's file alone. The krbtgt key forges a ticket for anyone
	// and the other services' keys forge theirs, so a service (an NFS server)
	// must be given a keytab holding ONLY its own key, extracted from this one,
	// never this file. A service that reads this file can mint tickets for the
	// whole realm, and one without a pinned Principal would also accept a TGT
	// as a service ticket (go-authn/krb5 refuses that since v0.5.0).
	Services *keytab.Keytab

	// Lifetime caps a ticket. Zero means ten hours, which is MIT's default.
	Lifetime time.Duration

	// MaxSkew is how far a client's clock may be from this one. Zero means
	// five minutes, which is what every Kerberos implementation assumes.
	MaxSkew time.Duration

	// MintCallers lists who may ask [Server.MintHandler] for a TGT on behalf of
	// a person they authenticated elsewhere (a passkey login at bridge): the
	// URI subjectAltNames of their TLS client certificates, matched exactly,
	// e.g. "https://login.example.org". Empty, the default, disables minting.
	MintCallers []string

	// AllowPasswordDerivedAS enables the AS exchange this KDC runs: a client
	// proves a password by encrypting a timestamp under a key the KDC derives
	// from the password the directory holds (RFC 3962 string-to-key). False, the
	// default, refuses an AS-REQ for a person whose directory entry holds a
	// password with KDC_ERR_POLICY (RFC 4120 §7.5.9), and Logf names this
	// option.
	//
	// ⛔ It is opt-in because the derivation needs the password itself, in the
	// clear, in the directory. Keys of services and krbtgt (the keytab), TGS and
	// the mint endpoint do not depend on it.
	AllowPasswordDerivedAS bool

	// Logf, when set, is told why a request was refused.
	//
	// It exists because the protocol cannot say: a client is given an error
	// CODE, and "pre-authentication failed" covers a wrong password, a wrong
	// salt, a clock an hour out and a malformed message. Only this side can
	// tell them apart, and only to an operator.
	//
	// ⛔ It is never given a password, a key, or a decrypted anything.
	Logf func(format string, args ...any)

	// PAC, when set, makes tickets for the listed services carry a Microsoft
	// PAC (MS-PAC) so that a service which insists on one (Samba as a domain
	// member) can build a token. Nil, the default, issues none: a standalone
	// Samba refuses a ticket whose PAC carries LOGON_INFO.
	PAC *PAC
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
	return c.checkPAC()
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

// hasKey says whether keyFor would find a password to derive from, without
// deriving anything.
func (c *Config) hasKey(id *directory.Identity) bool {
	_, err := id.Derive(func(string) ([]byte, error) { return nil, nil })
	return err == nil
}

// stringToKey is the derivation keyFor runs; a variable so that a test can
// count how often an unauthenticated request makes it run.
var stringToKey = rfc3962.StringToKeyIter

// keyFor derives a person's long-term key.
//
// The salt is the realm followed by the principal name with no separator,
// which is what RFC 4120 §4 specifies and what every client computes before it
// encrypts its timestamp. Getting it wrong produces a KDC that refuses every
// correct password, and says nothing about why.
func (c *Config) keyFor(id *directory.Identity) (types.EncryptionKey, error) {
	salt := c.saltFor(id)
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
		return derived.get(password, salt, func() ([]byte, error) { return stringToKey(password, salt, 4096, et) })
	})
	if err != nil {
		return types.EncryptionKey{}, err
	}
	return types.EncryptionKey{KeyType: defaultEtype, KeyValue: raw}, nil
}

// principalName renders a PrincipalName the way a realm writes it.
func principalName(p types.PrincipalName) string { return strings.Join(p.NameString, "/") }

// saltFor is the salt keyFor derives with, and the one the ETYPE-INFO2 hint
// names: one function, so the two cannot drift apart.
func (c *Config) saltFor(id *directory.Identity) string { return c.Realm + id.Name() }

// derived remembers the keys keyFor has derived.
//
// ⛔ Every AS-REQ carrying a PA-ENC-TIMESTAMP needs the person's key, and a
// well-formed but false timestamp costs the sender a hundred bytes: without
// this, each one cost the realm a PBKDF2 of 4096 iterations (1.3 ms against
// 22 µs, measured), the same asymmetry v0.2.1 removed only for a request with
// no timestamp at all. MIT never derives per request: it keeps the keys. Here
// the directory keeps passwords, so the derivation is kept instead, keyed by
// a SHA-256 of the salt and the password -- a changed password is another
// entry, the old one never matches again -- and bounded.
var derived = &keyCache{m: map[[32]byte][]byte{}}

// maxCachedKeys bounds the cache: past it, an entry is dropped. A realm's
// people, not an attacker's names, fill it: a name the directory does not hold
// never reaches keyFor.
const maxCachedKeys = 65536

type keyCache struct {
	mu sync.Mutex
	m  map[[32]byte][]byte
}

func (c *keyCache) get(password, salt string, derive func() ([]byte, error)) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte{0})
	h.Write([]byte(password))
	var k [32]byte
	h.Sum(k[:0])
	c.mu.Lock()
	if v, ok := c.m[k]; ok {
		c.mu.Unlock()
		return append([]byte(nil), v...), nil
	}
	c.mu.Unlock()
	v, err := derive()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.m) >= maxCachedKeys {
		for old := range c.m {
			delete(c.m, old)
			break
		}
	}
	c.m[k] = append([]byte(nil), v...)
	c.mu.Unlock()
	return v, nil
}
