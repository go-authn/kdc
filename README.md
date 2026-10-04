# kdc

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/kdc.svg)](https://pkg.go.dev/github.com/go-authn/kdc)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/kdc/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/kdc/actions/workflows/ci.yml)

**Issue Kerberos tickets from a [go-authn/directory](https://github.com/go-authn/directory), in Go, with no cgo.**

```go
srv, err := kdc.New(kdc.Config{
    Realm:    "EXAMPLE.ORG",
    People:   people,          // sqldir, hcldir — anything holding passwords
    Services: keytab,          // krbtgt/REALM, and a key per service
    Logf:     log.Printf,      // why each request was refused; nil says nothing
})
go srv.ServeUDP(pc)
go srv.ServeTCP(ln)
```

This is the **issuing** half. [go-authn/krb5](https://github.com/go-authn/krb5)
is the accepting half, and a service that only verifies tickets needs this
package not at all.

## ⛔ What can and cannot back a realm

A KDC must **decrypt** the client's pre-authentication with that person's
long-term key. It follows that only a source holding the **password** can back
one: `sqldir` and `hcldir` can, and a `Verifier` — a bind against somebody
else's LDAP, or a hash comparison — **cannot**, however well it answers "is
this the right password".

That is a property of Kerberos rather than a limitation here. `New` cannot see
it — a directory answers person by person — so the refusal comes at the
request: a person whose source holds no password is answered
`KDC_ERR_NULL_KEY` (MIT's `kinit` says *null key*), never the code a wrong
password gets, so it reads as a configuration to fix rather than a password to
retype. What `New` does refuse up front is a realm with no name, no directory,
no keytab, or a keytab without `krbtgt/REALM`.

## What it implements

AS-REQ and TGS-REQ, over UDP and TCP, with encrypted-timestamp
pre-authentication **required**.

What an unauthenticated peer can hold is bounded: a TCP message, its length
included, must arrive within 30 seconds; at most 256 TCP connections are served
at once, and one more is closed on accept; at most 64 datagrams are answered at
once, and one more is dropped (the client resends, or falls back to TCP).

Not implemented: cross-realm referrals, PKINIT, FAST, renewable or postdated
tickets, and any kadmin protocol. Keys come from the directory and from a
keytab, and they change where they live.

## What the TGS checks

A TGS-REQ buys a ticket only when all of this holds (RFC 4120 §3.3.2):

- the ticket presented is a **ticket-granting ticket of this realm**: it
  names `krbtgt/REALM` and is decrypted under that key, named by the KDC,
  not under the key of whatever service the ticket says it is for. Before
  v0.3.1 a service ticket forged with one service's key bought tickets for
  any other (`KRB_AP_ERR_NOT_US`);
- the authenticator decrypts under the session key inside it, within
  `MaxSkew` of this clock;
- the authenticator's **checksum is over this request's body**, as the bytes
  arrived, with the session key's own keyed checksum. A missing or unkeyed
  checksum is `KRB_AP_ERR_INAPP_CKSUM`, and a wrong one `KRB_AP_ERR_MODIFIED`.
  Versions up to v0.3.2 never read it, so anybody on the path could rewrite the
  service, lifetime or nonce of a request in flight;
- the client is of this realm and still in the directory
  (`KDC_ERR_C_PRINCIPAL_UNKNOWN` otherwise).

## How long a ticket lives

`Config.Lifetime` caps a ticket, ten hours when zero (MIT's default), and a
client asking for less gets less. `Config.MaxSkew` is how far a client's clock
may be from this one, five minutes when zero.

Since nothing revokes a Kerberos ticket, its end is the whole of how a password
change or a removed person comes to matter, so the TGS holds a TGT to it:

- a TGT past its end time is refused with `KRB_AP_ERR_TKT_EXPIRED`, and one
  before its start time, or flagged invalid, with `KRB_AP_ERR_TKT_NYV`. Those
  times were written by this KDC's clock, so no skew is allowed them;
- a ticket bought with a TGT ends no later than that TGT, so asking for
  `krbtgt` again cannot stretch a credential one lifetime at a time.

An AS-REQ without pre-authentication is answered without deriving the
person's key: PBKDF2 runs only once there is a timestamp to check, so a
spoofed UDP packet naming a real principal costs the realm no key derivation.

## One encryption type

Tickets and keys are made with **`aes256-cts-hmac-sha1-96`** (etype 18), and
nothing else is issued. A request whose etype list does not include 18 is
answered `KDC_ERR_ETYPE_NOSUPP` (RFC 4120 §3.1.3), before anybody is looked up,
rather than handed a reply it could not decrypt. It is what every Kerberos implementation in use agrees on, so
this costs no interoperability that a modern client would notice.

The realm says so rather than leaving it to be discovered. The `KRB-ERROR`
that demands pre-authentication carries an `ETYPE-INFO2` hint naming that
etype and the salt (the realm followed by the name, which is what the key is
derived with) — which is where a client looks before it derives a key, and why
the exchange starts with a refusal rather than a reply. Before v0.3.0 the salt
was left out: clients fell back to the default salt, which happens to be this
one, so nothing failed and nothing showed it.

A client that lists 18 but encrypts its timestamp under something else fails
pre-authentication and is answered `KDC_ERR_PREAUTH_FAILED` — the same code a
wrong password gets, because an unauthenticated caller is told no more than
*no*. With `Logf` set, the log records **both** etypes, its own and the
client's (and, for `ETYPE_NOSUPP`, the list offered), so an operator can tell a
mismatched cipher from a mistyped password.

## The judge

MIT's own `kinit` and `kvno`. **No MIT KDC is involved** — the keytab is built
in Go and only the *client* is borrowed, which is the point: a realm judged by
a client it did not write.

```sh
go test ./...          # KDC_REQUIRE_JUDGE=1 turns a missing MIT into a failure
```

The tests also pin the refusals a real client never triggers: a timestamp
under the wrong key, one from an hour ago, a three-byte cipher, a service
asked for straight from an AS-REQ, and a realm backed by a verifier.

## Licence

BSD-3-Clause.
