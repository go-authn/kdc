# MIT krb5kdc reads our CAMMAC

Question: does MIT accept the RFC 8129 CAMMAC (authentication indicator) that
go-authn/kdc writes into its TGTs, signed with the krbtgt key?

The image is Debian 13's `krb5kdc` (MIT 1.21) for realm FLEET.TEST, with the
krbtgt key of the test (same password, same AES-256 key, kvno 2) and four
services whose `require_auth` string names the indicator MIT demands
(`svc/plain`, `svc/passkey`, `svc/machine`, `svc/either`). The test seals TGTs
with the module's own `newTGT`, sends TGS-REQs over TCP and reads MIT's answer.

    MIT_CAMMAC=1 go test -run TestMITAcceptsTheCAMMACWeIssue -v .

Needs docker. Without `MIT_CAMMAC=1` the test is skipped; the `mit-cammac` CI
lane sets it and checks the test passed and that MIT logged a refusal.

MIT drops a container it cannot verify without an error, so a positive row
proves the container was read only because its negative twin (indicator
rewritten with the MAC kept, ticket changed after sealing, container dropped)
is refused with KDC_ERR_POLICY. Source read: krb5 5966c6bc `src/kdc/cammac.c`
(`cammac_check_kdcver`), `src/kdc/kdc_authdata.c` (`get_auth_indicators`),
`src/kdc/kdc_util.c` (the require_auth check); RFC 8129 section 3, RFC 4120
section 5.2.6. The passwords in the Dockerfile are those of a throwaway realm.
