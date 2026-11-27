# Design: D7, the asserted-identity SID for minted tickets

Status: DESIGN, not implemented. It makes decision D7 of
[pac.md](pac.md) implementable. pac.md lines 3-7 say D7 "is not applied" and
give no reason. This document gives the reason, proposes a mechanism, and lists
the decisions that are the owner's.

D7, as relayed on 2026-11-26: service tickets whose identity came from a
bridge-minted TGT carry S-1-18-1 (AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY)
in the PAC. Password AS exchanges carry S-1-18-2 (SERVICE_ASSERTED_IDENTITY),
or no such SID. **The specifications give these two SIDs the opposite
meanings** (see "What the SIDs mean"). That conflict is decision U1 below.
The mechanism does not depend on how U1 is answered.

## Sources opened

| Source | Version | Parts used |
|---|---|---|
| [MS-DTYP] | page updated 2024-11-20 | §2.4.2.4 Well-Known SID Structures, rows S-1-18-1 to S-1-18-6 |
| [MS-KILE] | page updated 2026-11-11 | §3.3.5.6.4.1 KERB_VALIDATION_INFO Structure; §2.2 pre-authentication types |
| [MS-SFU] | page updated 2026-03-30 | §3.2.5.1.2 KDC Replies with Service Ticket (S4U2self) |
| RFC 4120 | | §1.5.1, §2.1 (PRE-AUTHENT, HW-AUTHENT), §5.2.6 ("All negative values are reserved for local use"), §5.2.6.1, §5.2.6.2 |
| RFC 8129 | | §3, §4, §5 (authentication indicators) |
| MIT krb5 | master at 5966c6bc23d4d6e59c6a6bf70eed99cb589d7500 | `src/kdc/cammac.c` (whole file), `src/kdc/kdc_authdata.c:108-154, 302-384`, `src/kdc/do_tgs_req.c:764, 898, 1042` (grep hits only), `src/include/krb5/krb5.hin:1001` |
| Samba | v4-22-stable at 2750ed68433690b5f72c54ae54226e89ee1b9d74 | `source4/kdc/wdc-samba4.c:96-102`, `source4/kdc/pac-glue.c:783-815`, `librpc/idl/security.idl:317-333` (grep hits) |
| go-authn/kdc | v0.12.1, origin/main at 415ef18 | `mint.go`, `as.go:164-229`, `tgs.go`, `pacissue.go`, `internal/pac/pac.go:15-205`, `additional_tickets.go:1-65` |
| go-authn/bridge | v0.40.0, origin/main at c986d86 | `internal/app/kerberos.go:146-299` |

Not opened, so not relied on: RFC 7751 (CAMMAC; MIT's implementation was read
instead), RFC 6711, the MS-DTYP and MS-KILE product-behavior notes (<37>-<44>,
<60>), MS-SFU note <22>, Heimdal's KDC, and Windows' handling of unknown
authorization data in a service ticket.

## The implementer's inference, checked

"At TGS time a minted TGT is indistinguishable from an AS-issued one." This is
**true** on v0.12.1:

| Field of the TGT | AS path | Mint path |
|---|---|---|
| Flags | INITIAL, PRE-AUTHENT (`as.go:178-180`) | INITIAL, PRE-AUTHENT (`mint.go:105-107`) |
| Authorization data | none (`as.go:224`, `messages.NewTicket` takes none) | none (`mint.go:108`, the same call) |
| authtime | `now()`, whole seconds once DER-encoded (`as.go:168, 177`) | `now()` truncated to the second (`mint.go:97`) |
| Lifetime | up to `Config.Lifetime` (`as.go:189`) | up to `min(Config.Lifetime, 10 h)` (`mint.go:90`): a short TGT may come from either path |
| cname, sname, realm, key | same shapes | same shapes |

At the TGS, `issue` receives the TGT's `EncTicketPart` as `header`
(`tgs.go:145`, `as.go:166`). It reads two flags and the authtime from it
(`as.go:181-187`). `pacTicket` (`pacissue.go:303`) builds the PAC from the
directory and nothing else. Nothing in the ticket records which path made it,
so there is nothing to key S-1-18-1 on. The mechanism below adds that record.

A second fact matters as much. A TGS-REQ for `krbtgt/REALM` with a TGT
re-issues a TGT through the same `issue` (`tgs_krbtgt_internal_test.go`
covers it), and that TGT carries no authorization data. **Any marker must
survive that exchange.** Otherwise one TGS-REQ turns a minted TGT into one
that reads as AS-issued.

## What the SIDs mean

- [MS-DTYP] §2.4.2.4: S-1-18-1 is "the client's identity is asserted by an
  authentication authority based on proof of possession of client
  credentials". S-1-18-2 is "the client's identity is asserted by a service".
  S-1-18-3 FRESH_PUBLIC_KEY_IDENTITY is "asserted by an authentication
  authority based on proof of current possession of client public key
  credentials". S-1-18-4 KEY_TRUST_IDENTITY: "based on proof of possession of
  public key credentials using the key trust object".
- [MS-KILE] §3.3.5.6.4.1: for an ordinary logon, "the ExtraSids field SHOULD
  contain the AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY SID". A Windows DC
  puts S-1-18-1 on a **password** logon.
- [MS-SFU] §3.2.5.1.2 (S4U2self, where a service obtains a ticket for a user
  who never authenticated to the KDC): the KDC "MUST NOT include the
  AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY SID in the ExtraSids field and
  SHOULD add the SERVICE_ASSERTED_IDENTITY SID ... instead".
- Samba's KDC does exactly that: S-1-18-2 when the request is S4U2self,
  S-1-18-1 otherwise (`wdc-samba4.c:98-102`, `pac-glue.c:791-815`).

The bridge path is structurally S4U2self: a service (bridge, authenticated
to the KDC by mTLS) asserts an identity the KDC never saw proven. By the
letter of [MS-SFU] that is S-1-18-2, and the password logon is S-1-18-1. D7 as
relayed assigns them the other way round. An administrator who writes ACLs
from Microsoft's documentation ("deny S-1-18-2 to refuse protocol transition")
would then lock out password users and admit minted ones. See U1.

There is an argument for S-1-18-1 on minted tickets as well. The bridge
verified a WebAuthn assertion, which is proof of possession, and bridge and
KDC together form one authentication authority. pac.md D7 made exactly that
argument. It supports S-1-18-1 for both paths. It does not support S-1-18-2
for passwords.

## What the bridge actually asserts

`POST /kerberos/tgt` (`kerberos.go:232`) mints for whatever bearer token it is
given, not only for passkey logins:

- a person whose token came from a passkey login;
- a person whose token came from a federated IdP (`kerberosPrincipal`,
  `kerberos.go:186-205`), where the bridge relays someone else's assertion;
- a machine with a `client_credentials` token (`machineName`,
  `kerberos.go:216-228`).

"Minted" therefore does not mean "passkey". If the SID is meant to say
"passkey", the bridge has to tell the KDC which method it saw. `MintRequest`
(`mint.go:54-60`) has no field for that today. See U3.

## Options

The marker has to be producible only by the KDC, survive a TGS-REQ for
krbtgt, and reach `pacTicket`.

### (a) A KDC-issued marker in the TGT's authorization data — RECOMMENDED

The mint path puts an element into the TGT's `EncTicketPart.authorization-data`.
The TGS reads it from `header.AuthorizationData`. It copies the element into
any krbtgt ticket it issues, and `pacTicket` maps it to ExtraSids. Three
encodings:

- **(a1) An RFC 8129 authentication indicator in a CAMMAC (recommended).** The
  structure is AD-IF-RELEVANT { AD-CAMMAC(96) { elements = AD-AUTHENTICATION-
  INDICATOR(97) { "bridge-passkey" }, kdc-verifier = checksum with the krbtgt
  key } }. This is MIT's own format (`cammac.c:55-127`, `kdc_authdata.c:302-340`).
  The kdc-verifier is a keyed checksum, key usage 64 (`krb5.hin:1001`), over
  the DER `EncTicketPart` whose authorization data is replaced by the CAMMAC's
  elements (`cammac.c:36-47, 74-85`). That is the same "recode the ticket"
  step the PAC ticket signature already does (`pacissue.go:271-286`). On the
  TGS side, MIT accepts indicators only from a CAMMAC whose kdc-verifier checks
  (`kdc_authdata.c:361-371`, `cammac.c:134-175`). RFC 8129 §3 lets the KDC
  "copy it from a ticket-granting ticket into service tickets". Its strings are
  "site-defined" and contain no colon. MIT acceptors expose them, so non-PAC
  services (NFS, sshd) could use the same signal. That is U5.
- **(a2) A private negative ad-type inside AD-IF-RELEVANT.** RFC 4120 §5.2.6:
  "All negative values are reserved for local use." This is simpler, needs no
  verifier and has no standard meaning. Within this KDC its integrity comes
  from the ticket encryption alone (see below). It is acceptable if U5 is "no".
- **(a3) A minimal PAC in the TGT.** This is rejected. A PAC without LOGON_INFO
  violates [MS-PAC] §2.4 ("exactly one", pac.md table), and a full TGT PAC
  brings in the D5 transition and TGS-side PAC parsing, which pac.md's
  implementation deliberately avoided. That is a large cost for one bit.

**Forgery.** The TGT's `EncTicketPart` is encrypted under the krbtgt key with
aes256-cts-hmac-sha1-96, which authenticates the plaintext. Only the KDC can
write it. The TGS trusts authorization data only from a ticket that decrypted
under krbtgt (`tgs.go:62-72`), never from one encrypted under a service key.
Two invariants keep this true, and each needs a test:

1. Only `Mint` (and the TGS copying from a verified TGT) writes the marker.
   Today the only writer of `AuthorizationData` is `pacissue.go:276`.
2. Client-supplied `enc-authorization-data` from a TGS-REQ is never copied into
   a ticket. Today it is only parsed by a guard (`additional_tickets.go:81`)
   and never used. MIT needs `is_kdc_issued_authdatum` (`kdc_authdata.c:108-154`)
   precisely because it does copy client authorization data. If this KDC ever
   copies it, that filter becomes mandatory.

The CAMMAC kdc-verifier adds protection for one future case. If S4U2proxy
arrives, evidence tickets encrypted under a **service** key come back to the
TGS. A service-key holder could then plant a marker that ticket encryption
alone would not stop. The krbtgt-keyed verifier does stop it. This is the
reason to prefer (a1) over (a2).

**What a client can strip or downgrade.** It cannot strip or edit the marker:
it is inside the encrypted part. What it can do is **choose** which TGT to
present, if it holds both a password and a passkey. Because the marker is only
ever ADDED, every failure mode (a pre-upgrade TGT, a lost marker, an
unparsable element) reads as "AS". **Design rule:** the SID given to the
unmarked case must be the less privileged one in ACLs. ACLs grant on presence
and never deny on presence. A deny ACE on a SID that can be missing fails open.

**Interop.** A TGT is opaque to clients: RFC 4120 clients never decrypt a
ticket. Windows LSA, MIT and Heimdal credential caches store it as bytes. In
this single-realm KDC no other KDC ever decrypts our TGT, so unknown
authorization data in a TGT reaches no third-party parser. In service tickets,
AD-IF-RELEVANT elements are ignorable: a server "MAY ignore the
uninterpretable element" (RFC 4120 §5.2.6.1). MIT's KDC emits CAMMACs in
service tickets routinely. **Not measured:** Windows SSPI and Samba's
Heimdal-built acceptor on a service ticket carrying a CAMMAC. The Samba
harness answers that before U5 defaults to "yes".

**Across a TGS-REQ.** For `sname = krbtgt/REALM`, the TGS copies the marker
unchanged into the new TGT. For a service, `pacTicket` maps it to ExtraSids.
For a service without a PAC, it is dropped, unless U5 is "yes". The marker
carries no service-specific content, so it is valid for any service. RFC 4120
§1.5.1 ("MUST ignore but propagate to derivative tickets any unknown
authorization data types") is about elements the TGS does not understand. This
one it understands and re-issues itself.

**Cost.** For (a1): a CAMMAC and indicator encoder of about 80 lines of ASN.1
on gofork; a bounded decoder for the TGS, fuzzed (the authorization data comes
from a ticket we encrypted, but the decoder stays bounded); `newTicket`
(`pacissue.go:246`) gains an extra-authdata parameter, and the mint path and
the non-PAC path both start using it; and about 100 bytes per TGT. No new key,
no state, and no change on the wire for clients.

### (b) A ticket flag or the transited field — rejected

- **A reserved flag bit.** RFC 4120 §5.2.8 assigns the bits. An unassigned one
  could be assigned tomorrow, and it is echoed in the clear-to-client
  `EncKDCRepPart`, where MIT and Heimdal clients print it. The bit is
  forgery-resistant, since it sits in the encrypted part, but it means nothing
  standard and holds no method.
- **HW-AUTHENT** is tempting: RFC 4120 §2.1 says it is carried forward, and
  this TGS already copies it (`as.go:182`). But its meaning is "hardware
  expected to be possessed solely by the named client". That holds for an
  attested device-bound passkey. It does not hold for a synced passkey, a
  federated login or a machine token. Setting it for "minted" would lie in a
  standard field. At most it is a possible extra (U6), never the marker.
- **The transited field** encodes the realm path. MIT and Heimdal acceptors
  check transited policy on service tickets, so a foreign encoding there gets
  tickets refused, and it was never meant to carry an assertion.

### (c) KDC-side state keyed by session key or authtime — rejected

- **authtime** is not unique: two logins in the same second collide, and it is
  known to the client.
- **Session key** is unique and secret. But it means a table of live session
  keys in the KDC process, which holds no durable state today (pac.md cites
  `realm.go:19-72`). It is lost on restart, and the loss silently turns minted
  TGTs into AS ones. It is not shared between replicas. It needs memory bounded
  by 10 h of mints. A key copied into a map widens what a memory disclosure
  exposes. Every property that (a) gets from the ticket itself, this has to
  rebuild.

### (d) A separate krbtgt key version for minted TGTs — viable, not recommended

Mint encrypts under a dedicated krbtgt kvno, and the TGS reads the path from
`ap.Ticket.EncPart.KVNO`. It is forgery-proof, there is no authorization data,
and the TGS decrypt is unchanged. But it overloads key rotation, the kvno is
in the clear, which is harmless, and it carries one bit and no method. It
also needs `tgs.go:66`, which asks for kvno 0 ("latest"), to select by kvno,
and every rotation now has two keys to keep in step.

## Plan (after the decisions)

1. `MintRequest` gains `method` (U3), from a closed set. An unknown value is
   refused with 400, never defaulted. bridge sends it from what it verified.
2. `Mint` adds the (a1) element. `issue` copies it from `header` when sname is
   krbtgt. `pacTicket` maps it to ExtraSids per U1 and adds the asserted-identity
   SID to every PAC.
3. While there: `logonInfo` sets UserFlags 0x20 (LOGON_EXTRA_SIDS,
   `pacissue.go:216`) with an empty ExtraSids today. Step 2 makes the flag
   true. [MS-KILE] §3.3.5.6.4.1 wants the SID and the D bit together.
4. Tests:
   - a minted TGT and its TGS-re-issued TGT both yield the SID;
   - an AS TGT yields the other mapping;
   - a TGT whose marker bytes were flipped and re-encrypted with a WRONG key is
     refused, and one re-encrypted with the krbtgt key but a bad kdc-verifier
     reads as unmarked;
   - client `enc-authorization-data` carrying the marker is ignored;
   - `FuzzCAMMACDecode`;
   - a Samba-harness row showing the SID in the session token (`whoami /groups`
     equivalent).
5. README, CHANGELOG, pac.md status line. MINOR bump: below v1, a new PAC field
   is a behaviour change.

## Observed while reading (not D7, recorded so they are not lost)

- pac.md's Threats table claims REQUESTOR_SID in every TGT as the
  CVE-2021-42287-class defence. TGTs carry no PAC (pac.md line 5-6), so that
  defence is not in place. A name deleted and re-created within a TGT's
  lifetime (up to 10 h) gets the new holder's PAC from the old TGT, because
  `pacTicket` looks the name up afresh (`pacissue.go:307`). The (a1) CAMMAC
  could carry the requestor's uidNumber at TGT time at no extra cost, and the
  TGS would compare it. That is U7.
- Service-ticket PACs include ATTRIBUTES_INFO (17) and REQUESTOR_SID (18)
  (`internal/pac/pac.go:186-187`, no `ServiceTicket` condition), while pac.md's
  table and [MS-KILE] §3.3.5.7.9 (as pac.md cites it) say TGT only. This was not
  checked against the spec here.

## Decisions for the owner

| # | Decision | Recommendation |
|---|---|---|
| U1 | The SID mapping. D7 as relayed (minted → S-1-18-1, password → S-1-18-2 or none) is the reverse of [MS-KILE] §3.3.5.6.4.1 and [MS-SFU] §3.2.5.1.2. | Password → S-1-18-1 (MS-KILE SHOULD). Minted → S-1-18-1 as well, plus a distinguishing SID: a domain-relative "authenticated through bridge" group SID (RID configurable), and optionally S-1-18-3 for the passkey method only. Never S-1-18-2 on password logons. If the owner keeps D7 as relayed, the README says it inverts Microsoft's meaning. |
| U2 | Marker encoding. | (a1) RFC 8129 indicator in a CAMMAC with a krbtgt kdc-verifier. (a2) only if U5 is "no" and S4U is ruled out for good. |
| U3 | What bridge asserts: one bit "minted", or the method (passkey / federated / machine). | The method, from a closed set. Only `passkey` maps to the passkey-specific SID. |
| U4 | TGTs minted before the upgrade (at most 10 h, `MaxMintLifetime`) carry no marker. | Accept them as unmarked. They read as AS for at most 10 h, which is the safe direction under the design rule. |
| U5 | Also put the indicator in service tickets, for MIT acceptors and non-PAC services. | Yes, per service, after the Samba and Windows harness shows the CAMMAC is ignored there. |
| U6 | Set HW-AUTHENT for attested device-bound passkeys. | No for now. It is a separate claim with its own meaning, and it needs AAGUID attestation policy in bridge. |
| U7 | Carry the requestor uidNumber in the same CAMMAC to restore the name-confusion check. | Yes. It is the same mechanism and closes a defence pac.md claims and does not have. |

[MS-DTYP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
[MS-KILE]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ae7c10ab-dbcd-4afd-b481-f0c02d7eebef
[MS-SFU]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/ad98268b-f75b-42c3-b09b-959282770642
[MS-PAC]: https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-PAC/%5bMS-PAC%5d.pdf
