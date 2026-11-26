# Samba (non-AD) behind three KDCs

Question: does Samba 4.22 (Debian 13), run as a NON-AD file server, accept
Kerberos SMB authentication with service tickets issued by go-authn/kdc, which
does not issue a PAC?

The harness puts the same Samba container behind go-authn/kdc, MIT `krb5kdc`
and Heimdal `kdc`, runs `kinit` + `smbclient --use-kerberos=required`, decodes
the service ticket with the service keytab to see whether it carries a PAC
(authorization data type 128, bare or in AD-IF-RELEVANT), and reads smbd's
level-10 log for the decision.

## Running

Normal CI needs no Docker: the test is skipped.

    SAMBA_INTEROP=1 go test ./interop/samba -run TestSambaMatrix -v -timeout 30m

Needs Docker. Images are built from `docker/` (`debian:trixie`). Output
(`matrix.md`, `matrix.json`, full smbd logs) goes to `$SAMBA_INTEROP_OUT`, or
`os.UserConfigDir()/go-authn-kdc-samba-interop`. The go-authn/kdc under test
runs in the test process, TCP, reached from containers as
`host.docker.internal:<port>`; MIT and Heimdal run in their own containers.

## Result (Samba 4.22.11-Debian-4.22.11+dfsg-0+deb13u1)

| KDC | PAC in service ticket | Samba accepts | Samba relaxation | Security cost |
|---|---|---|---|---|
| go-authn/kdc (this checkout) | no (empty authorization data) | yes | `server role = standalone server` only | identity = principal name, local lookup; no SIDs/groups |
| MIT krb5kdc 1.21.3-5+deb13u2 | yes (`1[128]`) | yes | none beyond the standalone role | same |
| Heimdal kdc 7.8.git20221117 (deb13u1) | no (`1[512]` only) | yes | none beyond the standalone role | same |

Control: with `server role = member server` (unjoined) go-authn/kdc and
Heimdal tickets are refused with `NT_STATUS_NO_IMPERSONATION_TOKEN`
(`Unable to find PAC in ticket from alice@..., failing to allow access`); the
MIT row gives `NT_STATUS_NO_LOGON_SERVERS` (PAC present, but no domain to
contact, so it is not a clean control).

Decisive smbd lines (go-authn/kdc and Heimdal, standalone):

    obtaining PAC via GSSAPI gss_inquire_sec_context_by_oid (Heimdal OID) failed: ... Ticket has no authorization data
    gensec_generate_session_info_pac: Unable to find PAC for alice@REALM, resorting to local user lookup
    Kerberos ticket principal name is [alice@REALM]
    found user alice in passdb, calling make_server_info_sam
    Successful AuthZ: [SMB2,krb5] user [WORKGROUP]\[alice] ...

Samba config that is not a relaxation but is needed: a dedicated keytab for
`cifs/<host>`, a `username map` entry `alice = alice@REALM`, and a passdb or
Unix user `alice`.

Security cost of the standalone role: Samba maps the Kerberos principal name
to a local account (no domain SIDs or groups from a PAC); authorization is the
username map and local accounts only; any KDC holding the service key is
trusted for identity. A domain-member Samba refuses PAC-less tickets.

## Not covered

- The KKDCP / bridge KRB-CRED path (`POST /kerberos/tgt`): the TGT here comes
  from a password AS exchange (`AllowPasswordDerivedAS`).
- Samba as AD DC or domain member: they need a PAC.

## Sources opened

- Samba v4-22-stable: `source3/librpc/crypto/gse.c`
  (`gensec_gse_session_info`, `gssapi_obtain_pac_blob`),
  `auth/gensec/gensec_util.c` (`gensec_generate_session_info_pac`: the
  `ROLE_STANDALONE` check and the `NT_STATUS_NO_IMPERSONATION_TOKEN` path).
- MIT krb5 1.21.3 `doc/admin/conf_files/kdc_conf.rst` (`disable_pac`).
- Heimdal 7.8.0 `kdc/windc.c` (`_kdc_pac_generate` without a windc plugin
  returns without a PAC), `kdc/kerberos5.c` (`generate_pac`,
  `_kdc_tkt_add_if_relevant_ad`). Ad-type 512 in the Heimdal ticket is
  observed, not identified.
