# MIT krb5 (Debian 13), built to run krb5_kdc_verify_ticket on a PAC we issued.
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev libkrb5-dev \
 && rm -rf /var/lib/apt/lists/*
COPY verify.c /src/verify.c
RUN gcc -Wall -Werror -o /usr/local/bin/verify /src/verify.c $(krb5-config --libs krb5) $(krb5-config --cflags krb5)
ENTRYPOINT ["/usr/local/bin/verify"]
