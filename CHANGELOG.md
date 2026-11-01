# Changelog

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
