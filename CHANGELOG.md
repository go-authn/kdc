# Changelog

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
