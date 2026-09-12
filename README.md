# kdc

Issue Kerberos tickets from a [go-authn/directory](https://github.com/go-authn/directory), in Go, with no cgo.

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
