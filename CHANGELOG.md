# Changelog

## v0.12.0

- Added: `Config.PAC` and `NewDomainSID`: service tickets for the named
  services carry a PAC ([MS-PAC]: LOGON_INFO, CLIENT_INFO, UPN_DNS_INFO,
  PAC_REQUESTOR, signatures 6, 7, 16, 19). RIDs are the directory's
  uidNumber/gidNumber; a client with no uidNumber, or two accounts sharing a
  number, is refused (`KDC_ERR_POLICY`). The default (`PAC == nil`) is
  unchanged: no PAC. Design: `docs/design/pac.md` (go-authn/kdc#49).

- `interop/samba`: Docker harness (skipped unless `SAMBA_INTEROP=1`) measuring
  Samba 4.22 as a non-AD server behind go-authn/kdc, MIT krb5kdc and Heimdal.
  Result: a standalone-role Samba accepts our PAC-less tickets. A new row puts
  a PAC-issuing go-authn/kdc behind a `member server` Samba with winbindd and
  the KDC's domain SID: ACCEPTED (smbclient lists the share; Samba's log shows
  the PAC decoded and `WORKGROUP\alice` mapped through `username map`). It
  needs `PAC.NetBIOSDomain` equal to Samba's `workgroup`; with another value
  Samba answers `NT_STATUS_NO_SUCH_USER`. MIT's own member-server control row
  still fails with no domain controller (`NO_LOGON_SERVERS`).

- Independent check of the signatures: `MIT_VERIFY=1 go test .` (needs Docker)
  builds `interop/mitverify`, a C program on MIT krb5 1.21, and runs
  `krb5_kdc_verify_ticket` (signatures 6, 7, 16, 19) and `krb5_pac_verify`
  (CLIENT_INFO) on a ticket we issued: accepted, and refused under a wrong KDC
  key. Samba is not that oracle: winbindd falls back to an unsigned decode.

- Fuzzing found one defect before release: a non-null pointer to zero groups
  made `LogonInfo` decode to a non-nil empty slice (round trip differed). Fixed
  in `internal/pac/ndr.go`; the regression input and a seed corpus for
  `FuzzLogonInfo` and `FuzzPACVerify` are committed.

## v0.11.0

- Breaking: the password-derived AS exchange is now an explicit opt-in,
  `Config.AllowPasswordDerivedAS`, false by default (go-authn/kdc#41). Off,
  an AS-REQ for a person whose directory entry holds a password is answered
  `KDC_ERR_POLICY` (12, RFC 4120 §7.5.9), with a reason and a `Logf` line that
  name the option. Keytab keys (krbtgt, services) are unaffected.
  A realm that relied on the old behaviour sets `AllowPasswordDerivedAS: true`.
  TGS, minting and KKDCP are unaffected.

## v0.10.0

Security audit 2026-11-21 (suspicions, go-authn/kdc).

- Breaking: at most 16 TCP connections per source address (per /64 for IPv6)
  are served at once. With only the global cap of 256, one host holding 256
  idle connections starved everyone else for 30 s (the listener itself never
  blocked: past the cap a connection is closed on accept).
- Docs: `Config.Services` and the README no longer say a service reads the
  same keytab as the KDC. That file holds the krbtgt key and every service's
  key; a service gets a keytab with only its own key.
- Checked and left unchanged: `mintablePrincipal` accepting `@` (directory
  names are email-style by design and are looked up exactly) and the RSA-MD5
  authenticator checksum (the same rule as MIT's; see the comment on
  `checkBodyChecksum`).

## v0.9.0

- Added: `Server.KKDCPHandler`, Kerberos over HTTPS ([MS-KKDCP]): POST a
  `KDC-PROXY-MESSAGE`, answered by the same dispatcher as UDP and TCP 88. POST
  only (405), bounded (413), strict DER with no trailing bytes, a matching
  length prefix and a `target-domain` (400), another realm 403. `FuzzKKDCP`,
  and MIT `kinit`/`kvno` over `https://` as the oracle. Windows' own client
  (the KdcProxy policy) was run against it too: it fetched `cifs/` through it
  with port 88 closed.
- Security: a KDC-REQ whose additional-tickets field is not a
  `[11] SEQUENCE` (RFC 4120 5.4.1) is dropped before gokrb5 decodes it.
  gokrb5 v8.4.4 `unmarshalTicketsSequence` indexes the second byte of that
  value and panics on a one-byte one, before any authentication; v0.4.5 already
  recovered from the panic, now the request never reaches it (#28). The
  recover stays for panics not yet found, and `FuzzHandle` now FAILS when a
  request reaches it instead of logging it.

## v0.8.0

- Added: `Server.Mint`, `Server.MintHandler` and `Config.MintCallers`: a TGT
  for a person with no key, asked for by an allowlisted caller over mutually
  authenticated TLS, returned as a KRB-CRED (RFC 4120 5.8). Off by default.
- Fixed: the TGS compares the client name and realm in the authenticator with
  the ticket's and answers `KRB_AP_ERR_BADMATCH` when they differ
  (RFC 4120 3.2.3, as MIT `rd_req_dec.c`; the name type is not compared) (#40).

## v0.7.0

- Fixed: a Windows client's TGS-REQ is accepted. Its authenticator checksum is
  RSA-MD5 (type 7), unkeyed but sealed under the session key; MIT krb5 accepts
  it. CRC32, MD4 and SHA-1 stay refused; a body altered after signing is
  `KRB_AP_ERR_MODIFIED`.
- Fixed: tickets and reply parts carry flags and a starttime. AS: `INITIAL |
  PRE-AUTHENT`; TGS: `PRE-AUTHENT` inherited, no `INITIAL`, authtime of the
  TGT.

## v0.6.0

- Added: `Finder`. When `Config.People` implements
  `Find(name) (*directory.Identity, bool, error)`, a request asks it instead of
  walking `Identities()` (#31). The returned identity's name must equal the
  principal exactly, or it is an unknown principal; an error is
  `KDC_ERR_SVC_UNAVAILABLE`. Measured with 10,000 people (CPU profile, shares,
  load 13): the walk was 0.79 s of 1.59 s in `handle`; with a `Finder` the
  lookup is below the profile's threshold and `handle` is 0.36 s, 0.27 s of it
  gokrb5's ASN.1 encoding. Allocations unchanged (510; the walk allocated
  nothing). Times not compared: the machine was loaded.
- Added: `BenchmarkASNoPreauthFinder`.

## v0.5.0

- Added: the lookaside of MIT's KDC (`src/kdc/replay.c`). A request seen
  before, byte for byte, gets its previous reply and is not worked again; a
  copy arriving while the original is in progress is dropped. Only AS-REP and
  TGS-REP are stored, for two minutes, under 10 MiB in all, oldest first.
  Unlike MIT, an entry past two minutes never answers, even on a quiet KDC
  where no insertion has purged it. Cost: two allocations per request
  (BenchmarkTGSReq 1784 to 1786, BenchmarkASNoPreauth 508 to 510; times not
  measured, the machine was loaded). Closes the lookaside half of #27.
- Not added, on purpose: an authenticator replay cache (RFC 4120 3.2.3). MIT's
  KDC disables it at the TGS; it would turn a UDP retransmission into
  `KRB_AP_ERR_REPEAT`.
- Tested (go-authn/authnd#74): a directory outage is `KDC_ERR_SVC_UNAVAILABLE`
  on AS and TGS with a correct password, and a Verifier is never called by
  Kerberos (`KDC_ERR_NULL_KEY`). No code change was needed.
- Added: `BenchmarkTGSReq`.

## v0.4.5

Security audit, fuzzing and chaos pass.

- Fixed: a single malformed AS-REQ or TGS-REQ could crash the process (gokrb5
  v8.4.4 `unmarshalTicketsSequence` panics before any authentication). A
  request that panics the decoder is now dropped and logged with its stack.
- Fixed: a request for a realm this KDC does not serve is answered
  `KDC_ERR_WRONG_REALM` instead of being served.
- Fixed: an unreadable directory is answered `KDC_ERR_SVC_UNAVAILABLE`, not
  `KDC_ERR_C_PRINCIPAL_UNKNOWN`.
- Fixed: a TGT starting inside `MaxSkew` in the future is accepted (clock step).
- Fixed: principal names from the network are quoted in the log (log forging).
- Fixed: `Close` could race `WaitGroup.Add` with `Wait` on both transports.
- Dependencies: golang.org/x/net v0.60.0 to v0.62.0 (GO-2026-6866,
  GO-2026-6860), go-authn/directory v0.15.0 to v0.16.1. GO-2026-5932
  (x/crypto/openpgp) has no fix upstream and is not called.
- Added: `FuzzHandle`, chaos test (framing errors, clock jumps, close under
  load), `BenchmarkASNoPreauth`.
