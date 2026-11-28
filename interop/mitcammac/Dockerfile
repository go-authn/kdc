# An MIT krb5 KDC (Debian 13 package krb5-kdc, MIT 1.21) for realm FLEET.TEST
# whose krbtgt key is one go-authn/kdc also holds (password-derived, so both
# sides compute the same AES-256 key: kvno 2 after cpw). The passwords are
# those of a throwaway test realm and are repeated in
# mit_cammac_internal_test.go.
#
# Services, by the authentication indicators MIT's require_auth demands of a
# ticket-granting ticket before it issues a ticket for them:
#   svc/plain    none
#   svc/passkey  bridge-passkey
#   svc/machine  bridge-machine
#   svc/either   bridge-passkey OR bridge-machine
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server \
 && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
RUN kdb5_util create -s -P masterpw \
 && kadmin.local -q "cpw -pw krbtgtpw -e aes256-cts-hmac-sha1-96:normal krbtgt/FLEET.TEST" \
 && kadmin.local -q "addprinc -pw alicepw alice" \
 && kadmin.local -q "addprinc -pw svcpw svc/plain" \
 && kadmin.local -q "addprinc -pw svcpw svc/passkey" \
 && kadmin.local -q "set_string svc/passkey require_auth bridge-passkey" \
 && kadmin.local -q "addprinc -pw svcpw svc/machine" \
 && kadmin.local -q "set_string svc/machine require_auth bridge-machine" \
 && kadmin.local -q "addprinc -pw svcpw svc/either" \
 && kadmin.local -q "set_string svc/either require_auth \"bridge-passkey bridge-machine\"" \
 && kadmin.local -q "getprinc krbtgt/FLEET.TEST" \
 && kadmin.local -q "get_strings svc/passkey" \
 && kadmin.local -q "get_strings svc/machine" \
 && kadmin.local -q "get_strings svc/either"
EXPOSE 88/tcp
CMD ["krb5kdc", "-n"]
