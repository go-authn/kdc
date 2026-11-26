# interop/automount: a Linux client automounts a Samba share with Kerberos

End-to-end proof, for a sysadmin who runs Proxmox with Debian 13 LXC
containers: a Debian 13 client mounts a Samba share at boot or on first access,
with Kerberos and **no human `kinit`**, against a MIT KDC and against a Heimdal
KDC.

The harness is a Go test package. It needs a Debian 13 machine that can run
unprivileged LXC containers; here a Tart VM stands in for the Proxmox host and
is also the client. Normal CI skips it: nothing runs without
`AUTOMOUNT_INTEROP=1`.

## Run

    tart clone ghcr.io/cirruslabs/debian:latest automount-debian13
    tart run automount-debian13 --no-graphics &
    AUTOMOUNT_INTEROP=1 go test ./interop/automount -run TestSetup -v   # about 80 s
    AUTOMOUNT_INTEROP=1 go test ./interop/automount -run TestMatrix -v -timeout 40m

`AUTOMOUNT_VM` names another VM, `AUTOMOUNT_KDC=mit|heimdal` and
`AUTOMOUNT_CASE=<id>` narrow the run, `AUTOMOUNT_OUT` is where `matrix.json`
and the installed files (`files/`) are written.

`TestDoc` (`AUTOMOUNT_DOC=1`) renders `doc/guide-fr.md` from `matrix.json` and
the installed files, so that every configuration in the guide is the one that
passed.

## The matrix

Every case runs once per KDC and passes only when all its checks hold. The
checks are on evidence read from the machines, never on a mount's exit code
alone: `findmnt` shows `sec=krb5`, smbd's log holds
`Successful AuthZ: [SMB2,krb5]` and no NTLM exchange, the KDC's log names the
principal that asked.

| id | case |
|----|------|
| U  | Samba username map: a principal with a slash, quoted or not |
| A1 | machine keytab, `/etc/fstab` line with `x-systemd.automount` |
| A2 | machine keytab, autofs |
| A3 | machine keytab but no `username=`: which principal `cifs.upcall` tries |
| B  | service account `svc-partage`, ticket kept by a systemd service and timer |
| C  | `multiuser,sec=krb5`: alice (per-user keytab), bob (pam_krb5 over ssh), a user with no ticket |
| N1 | negative: mount by IP address, no NTLM fallback (with a positive NTLM control) |
| N2 | negative: client clock +4 minutes (works) and +10 minutes (refused) |
| N3 | negative: tickets of 3 minutes, re-acquisition after a reconnect, with a no-timer control |
| N4 | negative: keytab with mode 0644 |

## What it does not prove

* `pct` itself: the keytabs travel through `lxc-attach` and base64, which is what
  `pct pull` followed by `pct push` do; the guide gives the real commands.
* A console or graphical PAM login: bob's ticket comes from `pam_krb5` at an
  `ssh` login.
* The clock skew is emulated with `faketime` around `cifs.upcall`, because the
  containers share the VM's clock.
