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

    // Off by default: an AS-REQ for a password-bearing person is refused
    // KDC_ERR_POLICY (RFC 4120 §7.5.9).
    // True derives each person's key from the password the directory holds.
    AllowPasswordDerivedAS: true,
})
go srv.ServeUDP(pc)
go srv.ServeTCP(ln)
```

This is the **issuing** half. [go-authn/krb5](https://github.com/go-authn/krb5)
is the accepting half, and a service that only verifies tickets needs this
package not at all.

⛔ The keytab given to `Services` is **the KDC's alone**: it holds the krbtgt
key and every service's key, each of which forges tickets. A service gets a
keytab with only its own key, never this file. One source address may hold 16
TCP connections at once (a /64 for IPv6), so a single host cannot starve the
rest of the 256 slots.

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

## Finding a person: give it an index

Every AS-REQ and TGS-REQ looks one person up. With a plain `directory.Source`
that is `Identities()` and a walk: with 10,000 people the walk was **half of an
AS-REQ's CPU** (#31), and a source that reads a database or an LDAP server on
`Identities()` is read in full by every request — **including an
unauthenticated one**. A source that keeps an index implements `kdc.Finder`:

```go
Find(name string) (*directory.Identity, bool, error)
```

and the realm asks it instead. The name must match **exactly** (a principal is
case-sensitive; an identity whose `Name()` differs is not believed), and an
error is answered `KDC_ERR_SVC_UNAVAILABLE`. authnd hands the realm its
refreshed snapshot this way, so the database is read on the refresh interval,
not per request.

## What it implements

AS-REQ and TGS-REQ, over UDP and TCP, with encrypted-timestamp
pre-authentication **required**. A reply over 1465 bytes (a ticket with a big
PAC) is not sent as a datagram: the client gets `KRB_ERR_RESPONSE_TOO_BIG` and
repeats over TCP (RFC 4120 §7.2.1).

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
  arrived, with the session key's own keyed checksum, or with RSA-MD5
  (cksumtype 7), the unkeyed form Windows sends: it sits inside the
  authenticator, which is sealed under the session key, and MIT krb5 accepts
  it (`comp_cksum` asks for a collision-proof checksum, not a keyed one).
  Any other checksum type, or none, is `KRB_AP_ERR_INAPP_CKSUM`, and a wrong
  one `KRB_AP_ERR_MODIFIED`. Versions up to v0.3.2 never read it, so anybody
  on the path could rewrite the service, lifetime or nonce of a request in
  flight;
- the client is of this realm and still in the directory
  (`KDC_ERR_C_PRINCIPAL_UNKNOWN` otherwise).

Issued tickets carry the flags RFC 4120 gives them: an AS ticket is `INITIAL`
and `PRE-AUTHENT`; a TGS ticket is not `INITIAL`, inherits `PRE-AUTHENT` and the
TGT's authtime; both carry a starttime.

## A TGT for a person with no key: minting

A person who logs in with a passkey has no password, so an AS-REQ for them is
`KDC_ERR_NULL_KEY`. `Config.MintCallers` (default empty: off) names the callers,
by the URI name of their TLS client certificate, who may ask `Server.MintHandler`
for a TGT for a principal they have just authenticated. The reply is a KRB-CRED
(RFC 4120 5.8) with a fresh session key, `INITIAL | PRE-AUTHENT`, never
renewable, at most ten hours (`MaxMintLifetime`, and `Config.Lifetime` if
lower). The principal must exist in the directory. Serve the handler only on a
listener with `tls.RequireAndVerifyClientCert`; a connection without a verified
chain mints nothing. The reply carries the session key in the clear, so the
transport is the encryption.

## Kerberos over HTTPS: the KDC proxy (MS-KKDCP)

`Server.KKDCPHandler` speaks [MS-KKDCP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38),
the protocol of Windows' KdcProxy policy and of MIT krb5's
`kdc = https://host/KdcProxy`, so clients reach the realm through port 443 and
port 88 need not be open to the internet. A client POSTs a `KDC-PROXY-MESSAGE`
([section 2.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5778aff5-b182-4b97-a970-29c7f911eef2):
`kerb-message` with its 4-octet length, `target-domain`, optional
`dclocator-hint`); the message goes to the same dispatcher as a datagram on UDP
88 or a message on TCP 88, and the reply comes back in the same envelope
(`Content-Type: application/kerberos`). Put it behind a reverse proxy that
terminates TLS (Windows requires HTTPS) on a path such as `/KdcProxy`.

It answers what port 88 answers and refuses what it cannot answer: any method
but POST is 405; a body over the bound is 413; bytes that are not exactly one
DER `KDC-PROXY-MESSAGE`, a length prefix that disagrees with the message, a
missing `target-domain` or a message that is no Kerberos request is 400
([section 3.2.5.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/b5625a44-881a-4e5d-8a76-332d1a171059)
says to drop the connection on a malformed message; a status line costs nothing
and helps whoever debugs the client); another realm is 403. Nothing
authenticates the caller, as on 88. `FuzzKKDCP` (corpus committed) and a test
against MIT's own `kinit` and `kvno` over `https://` (`http_anchors`, the realm
reachable only through the proxy) judge it.

## What an unauthenticated peer can and cannot do (v0.4.5 audit)

- A request for **another realm** is `KDC_ERR_WRONG_REALM`, for both AS and
  TGS (MIT `do_as_req.c` does the same). Before v0.4.5 it was served.
- A **directory that cannot be read** is `KDC_ERR_SVC_UNAVAILABLE` (a client
  retries), no longer `KDC_ERR_C_PRINCIPAL_UNKNOWN` (a client gives up).
- A TGT whose start is within `MaxSkew` in the future is accepted, so a clock
  stepped back does not make freshly issued TGTs "not yet valid".
- A **malformed additional-tickets field** never reaches the decoder: `gokrb5`
  v8.4.4 panics on one (found by `FuzzHandle`), so a KDC-REQ whose field is not
  a `[11] SEQUENCE` is dropped first. Any other **panic in the third-party
  ASN.1 decoder** costs one request, not the process, and is logged with its
  stack; `FuzzHandle` fails on one.
- The TGS refuses an authenticator that names another client than its ticket
  (`KRB_AP_ERR_BADMATCH`, RFC 4120 3.2.3).
- Names taken from the network are quoted in the log.
- No account can be AS-REP-roasted: an AS-REQ without pre-authentication is
  always `KDC_ERR_PREAUTH_REQUIRED` (or `NULL_KEY`) and never a reply sealed
  under the person's key. Only aes256-cts-hmac-sha1-96 is issued; RC4 and DES
  are never.

- A request that arrives again **byte for byte** (a client that lost the reply
  over UDP, or a replayer) is answered with the reply it already had, without
  being worked again: MIT's lookaside (`src/kdc/replay.c`), ported. Entries
  last two minutes and are held under 10 MiB together; a `KRB-ERROR` is never
  stored, so a client told `KDC_ERR_SVC_UNAVAILABLE` is served afresh once the
  directory is back. There is deliberately **no authenticator replay cache**:
  MIT turns it off at the TGS (`kdc_util.c`, "Don't use a replay cache"),
  because a retransmission would then fail with `KRB_AP_ERR_REPEAT`, and a
  replayer cannot open a reply sealed under a key they do not hold.
- A directory that cannot be read is `KDC_ERR_SVC_UNAVAILABLE` on both the AS
  and the TGS, also for a correct password — never `PREAUTH_FAILED`, so it
  cannot count against a lockout. A source of Verifiers (an `ldap` upstream
  bind) is never asked by Kerberos: it is `KDC_ERR_NULL_KEY`.

## How long a ticket lives

`Config.Lifetime` caps a ticket, ten hours when zero (MIT's default), and a
client asking for less gets less. A `till` of `19700101000000Z` asks for the
longest ticket allowed (RFC 4120 5.4.1), which is what Heimdal's `kgetcred`
sends; a `till` already past is refused with `KDC_ERR_NEVER_VALID`, never
answered with a ticket expired on arrival. `Config.MaxSkew` is how far a client's clock
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

## An optional PAC

By default tickets carry no PAC, which is what a standalone Samba needs (it
refuses a PAC holding LOGON_INFO). A service that wants one (a Samba member
server, an SMB or NFS server mapping tickets to accounts) is named in
`Config.PAC`:

```go
sid, _ := kdc.NewDomainSID() // once, then keep it: it is the domain's identity
cfg.PAC = &kdc.PAC{DomainSID: sid, Services: []string{"cifs/files.example.org"}}
```

Those services' tickets carry `KERB_VALIDATION_INFO`, `CLIENT_INFO`, the
UPN/DNS info and the server, KDC, ticket and full signatures (16 and 19,
CVE-2022-37967). TGTs carry no PAC, but with `Config.PAC` set every TGT carries
a signed marking (an RFC 8129 CAMMAC in the krbtgt key, MIT's format): the
requestor's `uidNumber` and, for a bridge login, the method. The TGS refuses
(`KDC_ERR_TGT_REVOKED`) a TGT whose name now belongs to an account with another
`uidNumber`, which is the CVE-2021-42287 name-confusion defence; a forged or
unsigned marking is `KRB_AP_ERR_MODIFIED`. Every PAC then carries S-1-18-1
(authentication authority asserted identity) and the D bit; a bridge-minted TGT
adds a domain SID `<domain>-<MintedRID>` (default 1073741824). Minting
(`MintRequest.Method`: `passkey`, `federated` or `machine`) requires the method
when the PAC is on. TGTs issued before the upgrade carry no marking and are
accepted for `PAC.UnmarkedWindow` (default and maximum 10 h) after the KDC
starts, as password logons without the minted SID; `PAC.RefuseUnmarked` refuses
them at once. Design: `docs/design/pac-d7.md`. User and group RIDs are the
directory's `uidNumber` and `gidNumber`; a person with no `uidNumber` gets no
ticket for such a service (fail closed), two accounts sharing a number are
refused, groups without a `gidNumber` are left out, and at most 256 groups are
carried. Behind a Samba member server, set `PAC.NetBIOSDomain` to Samba's
`workgroup` (the PAC names that domain and Samba maps `WORKGROUP\alice`
through its `username map` or idmap). Tested against Samba 4.22, and the
signatures against MIT's `krb5_kdc_verify_ticket`. Design and measurements: [docs/design/pac.md](docs/design/pac.md).

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
