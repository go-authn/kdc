# Design: a PAC in go-authn/kdc tickets

Status: IMPLEMENTED (opt-in, `Config.PAC`) with deviations: the default is
`pac = none` (D6 amended: standalone Samba refuses LOGON_INFO), the PAC is built
at service-ticket time from the directory rather than copied from a TGT (TGTs
carry no PAC, so D5 and TGS-side PAC verification do not arise), and D7
(S-1-18-1) is not applied. Decided on 2026-11-26: go-authn/kdc issues a
PAC. This document covers what to build and how to prove it works. It ends
with the decisions that are the owner's to make.

## Why

A Samba file server in `server role = member server` refuses every ticket
this KDC issues today:

    Unable to find PAC in ticket from alice@..., failing to allow access
    NT_STATUS_NO_IMPERSONATION_TOKEN

That is `auth/gensec/gensec_util.c:56-81` in Samba v4-22-stable: no PAC and a
role other than `ROLE_STANDALONE` means refusal. It is measured by the harness
in `interop/samba/` on branch `interop-samba`. Only the standalone role
accepts our tickets today. It does so by looking the name up locally, which
gives no SIDs and no groups.

## Sources opened

| Source | Version | Parts used |
|---|---|---|
| [MS-PAC] | v20240610, rev. 26.0 | §2.3–2.10, 2.14, 2.15, §3 (sample), §4.1, notes <7> <10> <18> <19> |
| [MS-KILE] | v20261110 | §3.3.5.6.4 and its subsections, 3.3.5.7, 3.3.5.7.2, 3.3.5.7.9, 3.4.5.3 |
| Samba | `v4-22-stable` at 2750ed68433690b5f72c54ae54226e89ee1b9d74 (4.22.11) | `librpc/idl/krb5pac.idl`, `auth/kerberos/kerberos_pac.c`, `auth/gensec/gensec_util.c`, `source3/auth/auth_generic.c`, `source3/winbindd/winbindd_pam.c`, `source3/winbindd/winbindd_util.c`, `source3/winbindd/winbindd.c`, `source3/librpc/crypto/gse_krb5.c`, `source3/utils/net.c`, `docs-xml/manpages/idmap_rid.8.xml`, `idmap_autorid.8.xml` |
| MIT krb5 | master at 5966c6bc23d4d6e59c6a6bf70eed99cb589d7500 (2026-11-17) | `src/lib/krb5/krb/pac_sign.c`, `src/lib/krb5/krb/pac.c` |
| impacket | master at 7aa3770d59d76f90d5845dc21292d150f788b83c | `impacket/krb5/pac.py` (structure list) |
| gokrb5 | v8.4.4 | `messages/Ticket.go`, `pac/` (decoder only) |
| go-authn/directory | v0.17.0 | `identity.go`, `attributes.go`, `source.go` |
| this repository | `main` | `as.go`, `tgs.go`, `mint.go`, `lookup.go`, `realm.go` |

Not opened, so not relied on: RFC 4120 §7.2.1 (UDP size) and [MS-RPCE] §2.2.6
(type serialization). The latter is taken from Samba's IDL. Heimdal's
`lib/krb5/pac.c` was not opened either.

## What exists today

Three code paths make tickets. None of them carries authorization data.

- AS: `as.go:217` `messages.NewTicket(...)`.
- TGS: `tgs.go:145` → `issue` → `as.go:217`. The TGS reads nothing from the
  TGT's authorization data. It looks the client up again (`tgs.go:138`).
- Mint (bridge, passkey login): `mint.go:108`.

gokrb5's `NewTicket` (`messages/Ticket.go:57`) has no authorization-data
parameter. `EncTicketPart.AuthorizationData` exists (`Ticket.go:47`).

**Consequence:** we build and encrypt `EncTicketPart` ourselves. The ticket
signature (below) is computed over the DER of that structure, so we must
control its encoding byte for byte anyway.

The realm issues one etype only: aes256-cts-hmac-sha1-96, 18 (`realm.go:114`,
`as.go:277-292`). The krbtgt key and every service key are of that etype.

## Buffers we emit

PACTYPE: `cBuffers` count, `Version` = 0, every buffer at an 8-byte-aligned
u64 offset ([MS-PAC] §2.3, §2.4). The PAC is wrapped as AD-IF-RELEVANT(1) {
AD-WIN2K-PAC(128) } ([MS-KILE] §3.3.5.6.4). It is the FIRST authorization-data
element, as MIT places it (`pac_sign.c:389-394`).

| Type | Buffer | TGT | Service ticket | Why |
|---|---|---|---|---|
| 1 | LOGON_INFO (KERB_VALIDATION_INFO, NDR) | yes | yes | MUST, exactly one ([MS-PAC] §2.4). It is what winbindd turns into a token (`winbindd_pam.c:3592-3606`). |
| 10 | CLIENT_INFO | yes | yes | MUST. Samba refuses a PAC without it: `kerberos_pac.c:268-272` ("PAC no logon_name"). |
| 12 | UPN_DNS_INFO with the S extension (SamName + SID) | yes | yes | SHOULD. winbindd reads it (`winbindd_pam.c:3597`). The SID extension binds the name to the SID. |
| 17 | ATTRIBUTES_INFO | yes | no | SHOULD, TGT only ([MS-KILE] §3.3.5.6.4.7, removed per §3.3.5.7.9). |
| 18 | REQUESTOR_SID | yes | no | MUST, TGT only (§3.3.5.6.4.8, §3.3.5.7.9). It is the name-confusion defence, see Threats. |
| 6 | server signature | yes | yes | MUST. It is the only signature a member server can check (it holds no krbtgt key): `winbindd_pam.c:3504-3511` passes `krbtgt_keyblock = NULL`. |
| 7 | KDC signature | yes | yes | MUST. |
| 16 | ticket signature | no | yes | CVE-2020-17049 ([MS-PAC] notes <7> <18>). MIT adds it only when `k5_pac_should_have_ticket_signature(server)` holds (`pac_sign.c:396-406`). Read as "not a krbtgt ticket" from the name; that function's body was not opened. |
| 19 | full (extended KDC) signature | no | yes | CVE-2022-37966/37967 (notes <10> <19>). The same MIT rule applies (`pac_sign.c:239-258`). |

Not emitted: 2 (credentials, which are for PKINIT), 11 (delegation, since
this KDC does no S4U), 13/14/15 (claims and device, since we have no claims
model), and 20 (requestor GUID, MAY, no GUID exists).

Samba requires at least 4 buffers (`kerberos_pac.c:189-194`). The smallest
service ticket above has 6.

Unknown types are ignored by readers ([MS-PAC] §2.4), so the set can grow
later.

### KERB_VALIDATION_INFO field values

Per [MS-PAC] §2.5 and [MS-KILE] §3.3.5.6.4.1:

- **LogonTime**: the ticket authtime. **LogoffTime, KickOffTime,
  PasswordMustChange**: "never" (0x7FFFFFFF_FFFFFFFF). **PasswordLastSet,
  PasswordCanChange**: 0.
- **EffectiveName**: the account name. See decision D4. **FullName**: from a
  `displayName`/`cn` attribute if present, otherwise empty (Length 0). The
  logon script, profile, home directory and home drive are empty.
- **LogonCount, BadPasswordCount**: 0.
- **UserId**: the user's RID. **PrimaryGroupId**: the RID of the primary
  group. See D2 and D3.
- **GroupIds**: one RID per directory group, with attributes 7
  (mandatory | enabled-by-default | enabled, §2.2.1). The user's primary group
  is included.
- **UserFlags**: D (0x20, ExtraSids present). H is 0 because we have no
  resource groups. **UserSessionKey**: zero (MUST).
- **LogonServer**: the KDC's NetBIOS host name. **LogonDomainName**: the
  NetBIOS domain name. This MUST equal Samba's `workgroup`: winbindd looks the
  domain up by it (`winbindd_pam.c:3611` `is_allowed_domain`, `:3652`
  `find_lookup_domain_from_name`).
- **LogonDomainId**: the domain SID (D1).
- **UserAccountControl**: USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD.
- **ExtraSids**: S-1-18-1 (AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY) with
  attributes 7 (§3.3.5.6.4.1, "SHOULD"). See D7 for minted tickets.
- **ResourceGroupDomainSid, ResourceGroupIds**: NULL, count 0.

### CLIENT_INFO

ClientId is the FILETIME of the ticket's authtime. Name is the cname as
`krb5_unparse_name_flags(..., DISPLAY | NO_REALM)` prints it. MIT's acceptor
checks both strictly (`pac.c:418-434`): `pac_authtime != authtime ||
strcmp(...)` gives KRB5KRB_AP_WRONG_PRINC.

Two traps follow:

1. `as.go:168` takes `now().UTC()` with nanoseconds. The DER GeneralizedTime
   on the ticket keeps whole seconds. The FILETIME must be computed from the
   **same second-truncated value**, or every ticket fails MIT's check. Mint
   already truncates (`mint.go:97`); AS does not.
2. DISPLAY unparsing does not escape `@`. For a federated eppn principal
   `user@uni.fr`, the Name is `user@uni.fr`, not `user\@uni.fr`. A fixture
   with an `@` in the name is required.

## Signatures

The key usage is 17 (KERB_NON_KERB_CKSUM_SALT, [MS-PAC] §2.8.1). It equals
`KRB5_KEYUSAGE_APP_DATA_CKSUM`, which MIT uses (`pac_sign.c:207, 334`). The
checksum type follows the key's etype.

| Etype of key | SignatureType | Signature length |
|---|---|---|
| 18 aes256-cts-hmac-sha1-96 (the only one we issue) | 16 HMAC_SHA1_96_AES256 | 12 |
| 17 aes128-cts-hmac-sha1-96 | 15 HMAC_SHA1_96_AES128 | 12 |
| 23 rc4-hmac | 0xFFFFFF76 HMAC_MD5 | 16: **never produced, never accepted** |

Samba enforces the type/key pairing (`kerberos_pac.c:52-77`). The RFC 8009
types it also lists (sha256/384) are not issued by this realm.

### Which key signs what

| Signature | Key | Over |
|---|---|---|
| 16 ticket | krbtgt (etype 18) | DER `EncTicketPart` whose PAC element is replaced by AD-IF-RELEVANT{AD-WIN2K-PAC = one 0x00 byte} (§2.8.3, `pac_sign.c:306-340`, 389-404) |
| 19 full | krbtgt | the whole PAC with signatures 6, 7 and 19 zeroed (§2.8.5) |
| 6 server | the key that encrypts the ticket: the service's key, or krbtgt for a TGT | the whole PAC with every signature zeroed, after 16 and 19 are filled in (`pac_sign.c:260-266`) |
| 7 KDC | krbtgt | the signature bytes of 6 only (§2.8.4, `pac_sign.c:268-271`) |

The order is 16 → 19 → 6 → 7: placeholders first, then the header is frozen,
then signatures are computed in that order (§2.8.1, `pac_sign.c:230-271`).
The ticket signature is computed over the ENCODED ticket, so the DER encoder
used for it must be the one used for the real ticket. The real ticket differs
only in the PAC element's contents.

### At the TGS

Today's TGS regenerates everything from the directory (`tgs.go:138`). The
design keeps that, with checks added before issuing:

1. Find the PAC in the TGT (first AD-IF-RELEVANT element, type 128). Verify
   signature 6 with the krbtgt key (the TGT's server key) and signature 7 over
   it. A TGT has neither 16 nor 19.
2. Read REQUESTOR_SID. It MUST equal the SID the directory now gives the
   client name. Otherwise answer KDC_ERR_TGT_REVOKED ([MS-KILE] §3.3.5.7).
3. Check that CLIENT_INFO's authtime equals the TGT's authtime.
4. Build a FRESH PAC from the directory, so group changes take effect at the
   next TGS. Drop 17 and 18, add 16 and 19, and sign with the service key.

Only the PAC header, signature buffers, CLIENT_INFO and REQUESTOR_SID are
decoded at the TGS. KERB_VALIDATION_INFO is never parsed by the KDC, so the
NDR decoder stays out of the KDC's attack surface. See D5 for TGTs that have
no PAC (issued before the upgrade).

## NDR: hand-written encoder

**Recommendation: hand-write it.** Of the 9 buffers we emit, only LOGON_INFO
is NDR. CLIENT_INFO, UPN_DNS_INFO, ATTRIBUTES, REQUESTOR_SID and the
signatures are flat little-endian layouts. KERB_VALIDATION_INFO is one fixed
structure with:

- the MS-RPCE type-serialization v1 wrapper (Samba IDL
  `[subcontext(0xFFFFFC01)]`, `krb5pac.idl:186`): an 8-byte common header and
  an 8-byte private header holding the object length;
- a top-level unique pointer;
- RPC_UNICODE_STRINGs with deferred buffers;
- three conformant arrays: GroupIds, ExtraSids, ResourceGroupIds;
- 4-byte referent ids and 4/8-byte alignment.

That is a few hundred lines. A generator is not worth it:

- Samba's pidl is Perl. That is outside a Go-only toolchain, and it would
  bring an IDL compiler in to produce one structure.
- gokrb5 has a PAC decoder (`pac/`, on `jcmturner/rpc/v2/ndr`) but no encoder.

Our encoder writes; it never reads untrusted NDR (see "At the TGS").

**Tests:**

- **Round-trip against an independent decoder in-process**: every encoded
  PAC is decoded with gokrb5 `pac.PACType.Unmarshal` and the fields are
  compared. gokrb5 is a separate implementation from ours. It runs on every
  CI lane, with no Docker.
- **Fuzz** (`FuzzPACEncode`, corpus committed): arbitrary identities are
  encoded and decoded through gokrb5. Fuzzed inputs include names (UTF-16
  surrogates, NUL, 0–256 bytes, `@`) and 0–N groups. Asserted invariants:
  every offset is a multiple of 8; buffers do not overlap and lie within the
  PAC; field equality holds; the size is bounded.
- **Fuzz the TGS-side parser** (`FuzzPACVerify`) on arbitrary bytes. It must
  refuse, never panic, and allocate only within bounds. A count field must
  never drive an allocation before it is checked against the remaining
  length.
- **Known vector**: the annotated PAC in [MS-PAC] §3 (user "lzhu", domain
  S-1-5-21-397955417-626881126-188441444, buffers 1, 10, 6, 7) as a decode
  fixture for our TGS-side parser and for gokrb5. It carries an HMAC_MD5
  signature, which our verifier must REFUSE: that is the downgrade test.
- **Signing oracle**: MIT's PAC test program `src/lib/krb5/krb/t_pac.c` is
  the candidate source of known-key vectors (present in the reference clone,
  NOT yet read). If it holds none, the oracle is MIT `krb5_kdc_sign_ticket`
  run on our inputs in the harness container.
- **Out-of-process decoders** in the Samba container harness: Samba
  `ndrdump krb5pac PAC_DATA struct <file>` and impacket
  `impacket.krb5.pac` (`pac.py:219` PACTYPE, `:235` KERB_VALIDATION_INFO,
  `:394` VALIDATION_INFO). impacket has no constants for types 16 and 19
  (`pac.py:33-44`); it must skip them, which is itself a check that unknown
  types are tolerated.

**Size:** each group costs 8 bytes in GroupIds. With 100 groups a PAC is
about 1.5 KB, and the ticket travels twice in a TGS exchange. This KDC
answers UDP (`server.go:106`) and has no KRB_ERR_RESPONSE_TOO_BIG path. A cap
on groups in the PAC (refuse or truncate with a log line) and a TCP-retry
answer for big replies are part of the implementation. RFC 4120 §7.2.1 must
be opened for the latter.

## SIDs and RIDs

### Domain SID (D1)

The domain SID is configured as `S-1-5-21-x-y-z`, three 32-bit
sub-authorities after 21. Samba accepts exactly that form: `net setdomainsid`
requires `S-1-5-21-` and `num_auths == 4` (`net.c:451-458`).

It is generated once, at random, by an operator command (`kdc domainsid
new`), written into the KDC configuration, and given to each member server.
It is never derived from the realm name: two unrelated sites with the same
realm name must not share a SID space.

### RIDs for users and groups (D2)

Both must be stable, with no collision between any two principals, users and
groups together: they share one SID namespace under LogonDomainId. RIDs below
1000 are reserved: [MS-PAC] §4.1.2.2 treats well-known RIDs as forest-specific
and gives "R >= 1000" to user-created identities. Options:

| Option | Stable | Collision-free | State | Verdict |
|---|---|---|---|---|
| A. From a directory attribute: RID = `uidNumber` for users, `gidNumber` for groups, the attribute name configurable | as stable as the directory | only if uid and gid numbers are disjoint, checked at load | none new; the directory owns it | **recommended** |
| B. KDC allocates monotonically from 1000 and persists name → RID | yes | yes | a new durable store in the KDC, which has none today (`realm.go:19-72`) | if A is impossible |
| C. Keyed hash of the name into [1000, 2³¹) | yes, until a collision forces a change | no: with 10 000 names in 2³¹ the birthday bound gives ~2 % | none | rejected |

A, because the directory is the only party that sees every identity and
persists. go-authn/directory already carries `uidNumber`/`gidNumber` as
attributes (`identity.go:157`, README) for RFC 2307 deployments.

With idmap_rid and `base_rid` equal to the range's low end, Samba's uid
EQUALS the directory's uidNumber (`idmap_rid.8.xml:77`: ID = RID − BASE_RID +
LOW_RANGE_ID). Files written over NFS and SMB then have the same owner.

The KDC refuses to start, or refuses a PAC for the persons concerned (see
D3), when:

- a RID is below 1000 or above 2³¹−1;
- a user RID equals a group RID;
- two names share a RID.

The check walks `Identities()` and `GroupNames()` once at load and on each
refresh.

**The known weak spot:** user-private groups (gid == uid, common on Debian)
collide by construction. go-authn/authnd publishes people WITHOUT uidNumber
(directory `CHANGELOG.md:140`), and federated eppn principals have none
either. Those people get no PAC under A, and that is D3.

### Groups

Groups come from `Identity.Groups()` (`identity.go:194`), expanded through
`directory.Expand` (`source.go:349`) for nested `@group` members. A group's
RID comes from its `gidNumber` (`GroupAttributes`, `source.go:57`). A group
without one is left out of the PAC and logged; it is not given an invented
RID. The primary group is the group whose gidNumber equals the person's
gidNumber attribute. Without a gidNumber there is no primary group, and that
falls under D3.

## Samba member server: what it needs

From the code, not yet measured:

- `server role = member server` (or `security = ads`), with `workgroup` = our
  LogonDomainName and `realm` = our realm. winbindd exits without them
  (`winbindd.c:1465-1480`).
- **winbindd running.** Member mode hands the PAC to winbindd
  (`auth_generic.c:68-92`, NT_STATUS_NO_LOGON_SERVERS without it). That
  explains the MIT row of the PoC: the PAC was present, nothing verified it.
- **The domain SID in secrets.tdb**, with no AD join: winbindd's domain list
  needs `secrets_fetch_domain_sid(lp_workgroup())` ("did we join?",
  `winbindd_util.c:1221-1224`). `net setdomainsid S-1-5-21-x-y-z` stores
  exactly that (`net.c:460`).
- **The service key** through `kerberos method = dedicated keytab` and
  `dedicated keytab file = /etc/samba/cifs.keytab`. winbindd verifies
  signature 6 with each keytab entry (`gse_krb5.c:554-599`,
  `winbindd_pam.c:3486-3517`). **Warning:** if verification fails with
  ACCESS_DENIED, winbindd DECODES THE PAC ANYWAY, unsigned, and only skips the
  caches (`winbindd_pam.c:3575-3585, 3636`). A member server does not reject
  a PAC with a bad signature at that step. The ticket itself is still
  decrypted with the service key, so forging it needs that key (see Threats).
- **idmap.** Recommended:

      idmap config * : backend = tdb
      idmap config * : range = 3000-7999
      idmap config <WORKGROUP> : backend = rid
      idmap config <WORKGROUP> : range = 10000-999999
      idmap config <WORKGROUP> : base_rid = 10000   # uid == RID, if option A uses uidNumber >= 10000

  `autorid` (`idmap_autorid.8.xml`) is the alternative when uids need not
  match the directory. Its mapping is deterministic only per range allocation
  order (`:22`, `:83`), so two servers can disagree. `ad` and `ldap` need an
  AD-schema or Samba-schema LDAP that we do not publish.
- No `net ads join`: there is no AD DC, and the PAC path needs none.
  Whether a winbindd that cannot reach any DC still completes
  `create_local_token` for a PAC user (group SID → gid through idmap_rid, the
  netsamlogon cache primed at `winbindd_pam.c:3646`) is **not established**.
  The harness answers it.

**It breaks standalone mode.** A standalone Samba refuses a PAC that holds
LOGON_INFO: "Unexpected PAC for [...] in standalone mode",
NT_STATUS_BAD_TOKEN_TYPE (`auth_generic.c:228-238`). The PoC's standalone
deployments accept us today and would stop. MIT's PAC passes standalone mode
because it has no LOGON_INFO. See D6.

## Threats

| Threat | Defence |
|---|---|
| **PAC forgery by a client.** | The PAC is inside the encrypted ticket. Changing it needs the service key (service ticket) or the krbtgt key (TGT). Signatures 6 and 7 are checked at the TGS on every TGT ([MS-PAC] §4.1.1). |
| **Forgery by a service-key holder.** It can rewrite the PAC of tickets for ITS service; nothing stops that, and the same holds for Windows. It cannot make the KDC re-sign it: the TGS accepts only TGTs of this realm (`tgs.go:62-72`). | Signatures 16 and 19 are emitted anyway, for when S4U or renewal arrive (CVE-2020-17049 / 2022-37967 class). |
| **The krbtgt key extracted from the keytab.** Everything is forgeable. | Out of scope for the PAC. `realm.go:30-35` already says that file is the KDC's alone. |
| **Name confusion (CVE-2021-42287 class).** A TGT for name N is presented after N was deleted and re-created for someone else, or renamed. | REQUESTOR_SID in every TGT. The TGS refuses KDC_ERR_TGT_REVOKED unless the directory gives N the SAME SID now ([MS-KILE] §3.3.5.7). This works only if a re-created person gets a NEW RID; option C would break it, option A is as good as the directory's uidNumber reuse policy (D2). |
| **Collision between a local login and a federated eppn**, both arriving through a `directory.Set`. | The RID uniqueness check covers it. SamName and UPN are different strings. |
| **Downgrade: RC4/HMAC_MD5.** | Never produced. The TGS verifier accepts only SignatureType 16 with an etype 18 key, so the §3 sample PAC (HMAC_MD5) must be refused. |
| **Downgrade: a PAC-less TGT** presented after PAC issuance is on. | Refused once the transition window ends (D5). |
| **Downgrade: PAC stripped by the network.** | Impossible: the PAC is in the encrypted part. |
| **A forged CLIENT_INFO name or authtime.** | MIT acceptors check them (`pac.c:433`). Samba's own decoder checks LOGON_NAME against the client principal when it is given one (`kerberos_pac.c:389-414`). |
| **Resource exhaustion.** | A cap on groups per PAC. The TGS parser is bounded and fuzzed. |
| **Unsigned PAC accepted by winbindd** (`winbindd_pam.c:3575`). | A Samba behaviour, not ours. Stated so that nobody reads "member server verifies the PAC" as a proven gate. |

## Test oracle

1. **Samba harness** (`interop/samba/`, branch `interop-samba`). A new row,
   go-authn/kdc with PAC, against Samba 4.22 in `member server` role with
   winbindd, `net setdomainsid`, dedicated keytab and `idmap_rid`. It must go
   from **REFUSED** (NT_STATUS_NO_IMPERSONATION_TOKEN, today's control) to
   **ACCEPTED**, and the session must show:
   - the user SID `<domain SID>-<RID>`;
   - the directory groups (`smbclient ... -c 'whoami'` or smbd level-10
     "Successful AuthZ" with the SID list);
   - the uid equal to uidNumber.

   Run it for each principal shape: `alice`, and a federated `user@uni.fr`
   through `POST /kerberos/tgt`.
2. **Negative rows** in the same harness:
   - a service ticket whose PAC byte was flipped and re-encrypted with the
     service key is accepted by winbindd UNSIGNED (`winbindd_pam.c:3575`).
     This records what Samba does, not a fix;
   - a TGT whose REQUESTOR_SID no longer matches → KDC_ERR_TGT_REVOKED;
   - a TGT without a PAC after the window → refused.
3. **Standalone row**: it must show the D6 choice working. Either standalone
   keeps working through the per-service rule, or the row documents
   BAD_TOKEN_TYPE as expected.
4. **Decoders**: Samba `ndrdump` and impacket parse every PAC the harness
   captures, and their field dumps are compared with what the KDC meant to
   write.
5. **MIT `krb5kdc` 1.21.3** stays as the reference row. Its PAC is minimal
   (no LOGON_INFO) and is not a member-server control.

## Decisions for the owner

| # | Decision | Recommendation |
|---|---|---|
| D1 | Where the domain SID comes from. | Random once (`kdc domainsid new`), stored in config, given to Samba with `net setdomainsid`. Never derived from the realm. |
| D2 | RID source. | A: from `uidNumber`/`gidNumber` (attribute names configurable), uniqueness checked at load. B (KDC-persisted allocation) only if the directory cannot carry numbers. Never C (hash). |
| D3 | A person with no RID (no uidNumber: authnd users, federated eppn). | Issue the ticket WITHOUT a PAC: member servers refuse, standalone servers still work. Fail closed rather than invent a SID. If federated users must reach member servers, that forces B for them. |
| D4 | EffectiveName / SamName for `user@uni.fr`. | The principal unchanged, measured in the harness first. Samba may parse `@` as a UPN in name lookups (not verified). If it does, a deterministic SamName (the local part plus RID) with the full eppn in UPN_DNS_INFO. |
| D5 | PAC-less TGTs at the TGS after upgrade. | Accept them, and add a PAC ([MS-KILE] §3.3.5.7.2), for one maximum TGT lifetime after the PAC version starts (`Config.Lifetime`, at most 10 h for mint). Refuse after that, with a config switch whose default is refuse. |
| D6 | Standalone Samba deployments, which break on LOGON_INFO. | A per-service setting: `pac = full` (default) or `none` for named services (the AuthorizationDataNotRequired idea of §3.3.5.7). Documented in README as a breaking change: MINOR bump below v1. |
| D7 | ExtraSids for minted (passkey) TGTs. | S-1-18-1, the same as for AS: the bridge is an authentication authority this KDC trusts. Changing it to S-1-18-2 would need [MS-DTYP] opened first. |
| D8 | Group cap per PAC. | 256 groups. Above that the PAC is truncated, with a log line naming the person. Refusing would lock out people in many groups. |
| D9 | Whether groups appear only with a gidNumber. | Yes. A group without one is left out and logged. |

[MS-PAC]: https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-PAC/%5bMS-PAC%5d.pdf
[MS-KILE]: https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-KILE/%5bMS-KILE%5d.pdf
