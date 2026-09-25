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

That is a property of Kerberos rather than a limitation here. This package
refuses at configuration time, so an operator is told before the first
`kinit` rather than after.

## What it implements

AS-REQ and TGS-REQ, over UDP and TCP, with encrypted-timestamp
pre-authentication **required**.

Not implemented: cross-realm referrals, PKINIT, FAST, renewable or postdated
tickets, and any kadmin protocol. Keys come from the directory and from a
keytab, and they change where they live.

## One encryption type

Tickets and keys are made with **`aes256-cts-hmac-sha1-96`** (etype 18), and
nothing else is issued — the weaker types a client may offer are refused even
when asked for. It is what every Kerberos implementation in use agrees on, so
this costs no interoperability that a modern client would notice.

The realm says so rather than leaving it to be discovered. The `KRB-ERROR`
that demands pre-authentication carries an `ETYPE-INFO2` hint naming that
etype and the salt — which is where a client looks before it derives a key,
and why the exchange starts with a refusal rather than a reply.

A client that insists on something else fails pre-authentication and is
answered `KDC_ERR_PREAUTH_FAILED` — the same code a wrong password gets,
because an unauthenticated caller is told no more than *no*. The server log
records **both** etypes, its own and the client's, so an operator can tell a
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
