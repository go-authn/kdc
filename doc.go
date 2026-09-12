// Package kdc issues Kerberos tickets from a go-authn/directory.
//
// It is the other half of [github.com/go-authn/krb5], which accepts them. A
// service that verifies tickets needs no KDC and should not import this; a
// site that wants its own realm, backed by the same people its LDAP and its
// NFS already know, does.
//
// # What it can and cannot be backed by
//
// A KDC must DECRYPT the client's pre-authentication with that person's
// long-term key. It follows that only a directory source holding the PASSWORD
// can back one: sqldir and hcldir can, and a [directory.Verifier] — a bind
// against somebody else's LDAP, or a hash comparison — CANNOT, however well it
// answers "is this the right password".
//
// That is a property of Kerberos rather than a limitation here, and this
// package refuses at configuration time rather than at the first kinit.
//
// # What it implements
//
// AS-REQ and TGS-REQ over UDP and TCP, with encrypted-timestamp
// pre-authentication required. It does not implement cross-realm referrals,
// PKINIT, FAST, renewable or postdated tickets, or a kadmin protocol: keys
// come from the directory and from a keytab, and change where they live.
package kdc
