---
title: "Montage automatique d'un partage Samba avec Kerberos, sans kinit humain"
---

# Montage automatique Samba + Kerberos sous Debian 13 (Proxmox, LXC)

Ce guide décrit une preuve de bout en bout : un client Debian 13 monte un
partage Samba avec Kerberos (`sec=krb5`), au démarrage ou au premier accès,
sans que personne ne tape `kinit`. Il a été exécuté contre un KDC MIT et contre
un KDC Heimdal. **Toutes les configurations citées ci-dessous sont, mot pour
mot, celles qui ont été installées par le banc d'essai et qui ont passé** : le
document est produit par `TestDoc` à partir des mêmes fonctions et du
`matrix.json` de la dernière exécution.

## Ce qui a été et n'a pas été testé

* `pct` n'a **pas** été exécuté : le banc tourne dans une VM Debian 13 (Tart)
  qui joue à la fois l'hôte Proxmox (LXC non privilégiés, `lxc-attach`) et le
  client. Les transferts de fichiers `pct pull` / `pct push` sont émulés par
  `lxc-attach` et base64 ; les vraies commandes sont données plus bas.
* Pas de connexion console ou graphique : le ticket de `bob` vient de
  `pam_krb5` lors d'une connexion `ssh`.
* Le décalage d'horloge est émulé avec `faketime` autour de `cifs.upcall`, car
  les conteneurs partagent l'horloge de la VM.

## 1. Architecture

```
                 +--------------------+
                 |  KDC (LXC)         |   MIT : kdc-mit      10.0.3.11
                 |  realm POC.TEST    |   Heimdal : kdc-heimdal 10.0.3.12
                 +---------+----------+
                           ^  AS-REQ / TGS-REQ (UDP/TCP 88)
                           |
 +-------------------------+---------------------------+
 | client Debian 13 (client.poc.test, 10.0.3.1)        |
 |  mount.cifs -> noyau CIFS -> request-key            |
 |       -> cifs.upcall --keytab=/etc/krb5.keytab      |
 |       -> ticket de service cifs/samba.poc.test      |
 +-------------------------+---------------------------+
                           | SMB 3.1.1, SPNEGO / Kerberos
                           v
                 +--------------------+
                 |  Samba (LXC)       |   samba.poc.test  10.0.3.13
                 |  partage "partage" |
                 +--------------------+
```

## 2. Prérequis

Paquets installés sur l'hôte/client :

```
lxc debootstrap cifs-utils keyutils autofs krb5-user libpam-krb5 faketime openssh-server sshpass uidmap rsync
```


Les conteneurs sont des LXC **non privilégiés** avec le mappage suivant,
ajouté à leur configuration (`/etc/pve/lxc/<ctid>.conf` sous Proxmox ne le
demande pas, c'est le comportement par défaut ; le banc le pose dans
`/etc/lxc/poc-base.conf`) :

```
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536
```


Réseau d'un conteneur (`systemd-networkd`), exemple pour le serveur Samba :

```
[Match]
Name=eth0

[Network]
Address=10.0.3.13/24
Gateway=10.0.3.1
DNS=10.0.3.1
```


Résolution de noms sur le client et sur Samba (le KDC est désigné par son
adresse, le reste par `/etc/hosts`) :

```
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
10.0.3.1 client.poc.test client
10.0.3.11 kdc.poc.test kdc
10.0.3.13 samba.poc.test samba
```


Le fichier `/etc/krb5.conf` du client est le même pour les deux KDC :

```
[libdefaults]
  default_realm = POC.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  udp_preference_limit = 1
  default_ccache_name = FILE:/tmp/krb5cc_%{uid}

[realms]
  POC.TEST = {
    kdc = kdc.poc.test
    admin_server = kdc.poc.test
  }

[domain_realm]
  .poc.test = POC.TEST
  poc.test = POC.TEST
```


## 3. Le KDC

### 3.1 MIT (`krb5-kdc`, `krb5-admin-server`)

`/etc/krb5kdc/kdc.conf` :

```
[kdcdefaults]
  kdc_ports = 88
  kdc_tcp_ports = 88

[realms]
  POC.TEST = {
    database_name = /var/lib/krb5kdc/principal
    key_stash_file = /etc/krb5kdc/stash
    acl_file = /etc/krb5kdc/kadm5.acl
    max_life = 10h 0m 0s
    max_renewable_life = 7d 0h 0m 0s
    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  }
```


Création des principaux (le script est exécuté avec `kadmin.local`) :

```
kadmin.local -q 'addprinc -randkey alice'
```


Export d'un keytab. **`ktadd` tire une clé aléatoire et change donc le mot de
passe du principal** : on ne l'applique pas à un utilisateur dont on veut
garder le mot de passe (ici `bob`, qui se connecte avec `pam_krb5`).

```
rm -f '/etc/krb5/alice.keytab'; kadmin.local -q 'ktadd -k /etc/krb5/alice.keytab alice'
```


Le KDC MIT de Debian journalise **dans le journal systemd**
(`journalctl -u krb5-kdc`), quel que soit le `[logging]` du `krb5.conf` :
le fichier configuré est resté vide.

### 3.2 Heimdal (`heimdal-kdc`)

`/etc/krb5.conf` du conteneur KDC :

```
[libdefaults]
  default_realm = POC.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false

[realms]
  POC.TEST = {
    kdc = kdc.poc.test
    admin_server = kdc.poc.test
  }

[domain_realm]
  .poc.test = POC.TEST
  poc.test = POC.TEST

[kdc]
  database = {
    realm = POC.TEST
    dbname = sqlite:/var/lib/heimdal-kdc/heimdal.db
    mkey_file = /var/lib/heimdal-kdc/m-key
    log_file = /var/lib/heimdal-kdc/kdc.db.log
  }
  require-preauth = true
  ports = 88

[logging]
  kdc = FILE:/var/log/heimdal-kdc.log
  default = FILE:/var/log/heimdal-kdc.log
```


Création des principaux :

```
kadmin -l add --random-key --use-defaults 'alice'
```


Export d'un keytab :

```
rm -f '/etc/krb5/alice.keytab'; kadmin -l ext_keytab -k '/etc/krb5/alice.keytab' 'alice'
```


## 4. Le serveur Samba (LXC)

`/etc/samba/smb.conf` :

```
[global]
  workgroup = WORKGROUP
  netbios name = SAMBA
  server role = standalone server
  security = user
  realm = POC.TEST
  kerberos method = dedicated keytab
  dedicated keytab file = /etc/samba/cifs.keytab
  username map = /etc/samba/usermap
  map to guest = never
  ntlm auth = disabled
  server min protocol = SMB3
  disable netbios = yes
  smb ports = 445
  log level = 1 auth_audit:10 auth_json_audit:10 auth:3 kerberos:3
  log file = /var/log/samba/log.smbd
  max log size = 0

[partage]
  path = /srv/partage
  read only = no
  create mask = 0664
  directory mask = 0775
```


La table de correspondance (`username map`) doit accepter le principal de la
machine `root/client.poc.test`, qui contient une barre oblique. Mesure : Samba
retire le royaume et cherche la clé `WORKGROUP\<nom>` (source :
`source3/auth/user_krb5.c`, puis `map_username`). La barre oblique est
acceptée, avec ou sans guillemets ; une clé sans `WORKGROUP\`, ou avec
`@POC.TEST`, **échoue** (erreur 13).

Sans guillemets :

```
partage = WORKGROUP\root/client.poc.test WORKGROUP\svc-partage
```


Avec guillemets :

```
partage = "WORKGROUP\root/client.poc.test" WORKGROUP\svc-partage
```


Preuve (cas U) :

- PASS : plain, WORKGROUP\ key: mounted, Samba user partage
- PASS : quoted, WORKGROUP\ key: mounted, Samba user partage
- PASS : plain, no workgroup: refused (error 13), name invalid on this system
- PASS : quoted, no workgroup: refused (error 13), name invalid on this system
- PASS : with the realm: refused (error 13), name invalid on this system

```
# usermap plain, WORKGROUP\ key: partage = WORKGROUP\root/client.poc.test
mount rc=0 
  Kerberos ticket principal name is [root/client.poc.test@POC.TEST]
  Successful AuthZ: [SMB2,krb5] user [WORKGROUP]\[partage] [S-1-5-21-1336209348-4248724079-4267077521-1000] at [Thu, 26 Nov 2026 16:07:44.368609 UTC] Remote host [ipv4:10.0.3.1:40228] local host [ipv4:10.0.3.13:445]
```

```
# usermap plain, no workgroup: partage = root/client.poc.test
mount rc=32 mount error(13): Permission denied
Refer to the mount.cifs(8) manual page (e.g. man mount.cifs) and kernel log messages (dmesg)
  Kerberos ticket principal name is [root/client.poc.test@POC.TEST]
  get_user_from_kerberos_info: Username root/client.poc.test is invalid on this system
```


## 5. Les vraies commandes Proxmox

Sous Proxmox, les fichiers (keytab, `smb.conf`) passent entre l'hôte et un
conteneur par `pct`, et les commandes s'exécutent avec `pct exec`. **Elles
n'ont pas été lancées ici** ; le banc utilise `lxc-attach` et base64, ce qui
revient à `pct pull` puis `pct push`.

```
# lancer une commande dans le conteneur Samba (ctid 103)
pct exec 103 -- systemctl restart smbd

# récupérer le keytab de la machine sur le KDC (ctid 101)
pct exec 101 -- kadmin.local -q "ktadd -k /root/client.keytab root/client.poc.test"
pct pull 101 /root/client.keytab /root/client.keytab

# le poser sur le client (ctid 110), propriétaire root, mode 0600
pct push 110 /root/client.keytab /etc/krb5.keytab --perms 0600 --user 0 --group 0
```

Si le client est un conteneur, `cifs.upcall` s'exécute dans l'espace de noms
de l'hôte (le noyau l'appelle via `request-key`) : le montage CIFS d'un LXC
non privilégié n'est pas possible sans configuration supplémentaire. Le plus
simple est de monter sur l'hôte Proxmox ou dans une VM.

## 6. Le client : trois méthodes

### 6.0 Commun : `cifs.upcall` avec le keytab de la machine

Le noyau appelle `cifs.upcall` par `request-key`. Le paramètre `--keytab`
indique le keytab de repli quand l'utilisateur n'a pas de ticket.
`/etc/request-key.d/cifs.spnego.conf` :

```
create  cifs.spnego    * * /usr/sbin/cifs.upcall --keytab=/etc/krb5.keytab %k
```


Le principal de la machine est `root/client.poc.test@POC.TEST`, exporté dans
`/etc/krb5.keytab` (mode 0600, propriétaire root).

**Quel principal `cifs.upcall` essaie-t-il ?** Source : `cifs.upcall.c`
(cifs-utils). Si aucun cache utilisable n'existe et que `username=` est
renseigné, `init_cc_from_keytab(keytab, username)` demande un ticket pour
exactement ce nom, et lui seul. Sans `username=`, `mount.cifs` retombe sur
`$USER`, donc sur `root@POC.TEST`, qui n'existe pas dans le KDC. Le principal de
service est `cifs/<hôte tel que saisi>`. Il faut donc écrire
`username=root/client.poc.test@POC.TEST` :

- PASS : the mount is refused
- PASS : cifs.upcall tried user=root and found no key for it in the keytab
- PASS : the KDC was asked for root@POC.TEST (the login name), not for the machine principal
- PASS : smbd: no authorization at all

```
# cifs.upcall (journal)
key description: cifs.spnego;0;0;39010000;ver=0x2;host=samba.poc.test;ip4=10.0.3.13;sec=krb5;uid=0x3e8;creduid=0x0;user=root;pid=0x8a96;upcall_target=app
ver=2
host=samba.poc.test
ip=10.0.3.13
sec=1
uid=1000
creduid=0
user=root
pid=35478
upcall_target=app
upcall_target=app, switching namespaces to application thread
get_cachename_from_process_env: pid == 0
get_existing_cc: default ccache is FILE:/tmp/krb5cc_0
check_service_ticket_exists: unable to get client principal from cache: No credentials cache found (filename: /tmp/krb5cc_0)
get_tgt_time: unable to get principal
main: valid TGT is not present in credential cache
krb5_get_init_creds_keytab: -1765328203
handle_krb5_mech: getting service ticket for samba.poc.test
handle_krb5_mech: using GSS-API
GSS-API error init_sec_context: No credentials were supplied, or the credentials were unavailable or inaccessible
GSS-API error init_sec_context: No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_0)
handle_krb5_mech: failed to obtain service ticket via GSS (458752)
Unable to obtain service ticket
Exit status 458752
key description: cifs.spnego;0;0;39010000;ver=0x2;host=samba.poc.test;ip4=10.0.3.13;sec=krb5;uid=0x3e8;creduid=0x3e8;user=root;pid=0x8a96;upcall_target=app
ver=2
host=samba.poc.test
ip=10.0.3.13
sec=1
uid=1000
[...]
```


### 6.1 Méthode (a) : ligne `/etc/fstab` avec `x-systemd.automount`

`/etc/fstab` :

```
//samba.poc.test/partage /mnt/fstab cifs sec=krb5,vers=3.1.1,cruid=0,uid=1000,gid=1000,username=root/client.poc.test@POC.TEST,noauto,x-systemd.automount,x-systemd.idle-timeout=60,_netdev 0 0
```


Résultat, KDC MIT :

- PASS : the share is listed through the automount
- PASS : findmnt: fstype cifs with sec=krb5
- PASS : smbd: Successful AuthZ [SMB2,krb5] as partage
- PASS : smbd: no NTLM
- PASS : KDC: AS request for root/client.poc.test@POC.TEST

```
# findmnt
TARGET     SOURCE                   FSTYPE OPTIONS
/mnt/fstab //samba.poc.test/partage cifs   rw,relatime,vers=3.1.1,sec=krb5,cruid=0,cache=strict,upcall_target=app,username=root/client.poc.test@POC.TEST,uid=1000,forceuid,gid=1000,forcegid,addr=10.0.3.13,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,reparse=nfs,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1,closetimeo=1
```

```
# klist (no ticket cache, nobody ran kinit)
klist: No credentials cache found (filename: /tmp/krb5cc_0)
---
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   9 root/client.poc.test@POC.TEST
   9 root/client.poc.test@POC.TEST
```

```
# smbd (authentication lines)
  Kerberos ticket principal name is [root/client.poc.test@POC.TEST]
  Successful AuthZ: [SMB2,krb5] user [WORKGROUP]\[partage] [S-1-5-21-1336209348-4248724079-4267077521-1000] at [Thu, 26 Nov 2026 16:07:46.718248 UTC] Remote host [ipv4:10.0.3.1:40288] local host [ipv4:10.0.3.13:445]
```


Résultat, KDC Heimdal :

- PASS : the share is listed through the automount
- PASS : findmnt: fstype cifs with sec=krb5
- PASS : smbd: Successful AuthZ [SMB2,krb5] as partage
- PASS : smbd: no NTLM
- PASS : KDC: AS request for root/client.poc.test@POC.TEST

```
# findmnt
TARGET     SOURCE                   FSTYPE OPTIONS
/mnt/fstab //samba.poc.test/partage cifs   rw,relatime,vers=3.1.1,sec=krb5,cruid=0,cache=strict,upcall_target=app,username=root/client.poc.test@POC.TEST,uid=1000,forceuid,gid=1000,forcegid,addr=10.0.3.13,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,reparse=nfs,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1,closetimeo=1
```

```
# smbd (authentication lines)
  Kerberos ticket principal name is [root/client.poc.test@POC.TEST]
  Successful AuthZ: [SMB2,krb5] user [WORKGROUP]\[partage] [S-1-5-21-1336209348-4248724079-4267077521-1000] at [Thu, 26 Nov 2026 16:11:57.181878 UTC] Remote host [ipv4:10.0.3.1:52118] local host [ipv4:10.0.3.13:445]
```


### 6.2 Méthode (b) : autofs

`/etc/auto.master.d/poc.autofs` (une ligne) :

```
/mnt/autofs /etc/auto.poc --timeout=60
```


`/etc/auto.poc` :

```
partage -fstype=cifs,sec=krb5,vers=3.1.1,cruid=0,uid=1000,gid=1000,username=root/client.poc.test@POC.TEST ://samba.poc.test/partage
```


Résultat, KDC MIT :

- PASS : the share is listed through autofs
- PASS : findmnt: fstype cifs with sec=krb5
- PASS : smbd: Successful AuthZ [SMB2,krb5] as partage
- PASS : smbd: no NTLM
- PASS : KDC: AS request for root/client.poc.test@POC.TEST

```
# findmnt
TARGET              SOURCE                   FSTYPE OPTIONS
/mnt/autofs/partage //samba.poc.test/partage cifs   rw,relatime,vers=3.1.1,sec=krb5,cruid=0,cache=strict,upcall_target=app,username=root/client.poc.test@POC.TEST,uid=1000,forceuid,gid=1000,forcegid,addr=10.0.3.13,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,reparse=nfs,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1,closetimeo=1
```

```
# smbd (authentication lines)
  Kerberos ticket principal name is [root/client.poc.test@POC.TEST]
  Successful AuthZ: [SMB2,krb5] user [WORKGROUP]\[partage] [S-1-5-21-1336209348-4248724079-4267077521-1000] at [Thu, 26 Nov 2026 16:07:49.120156 UTC] Remote host [ipv4:10.0.3.1:40290] local host [ipv4:10.0.3.13:445]
```


Résultat, KDC Heimdal :

- PASS : the share is listed through autofs
- PASS : findmnt: fstype cifs with sec=krb5
- PASS : smbd: Successful AuthZ [SMB2,krb5] as partage
- PASS : smbd: no NTLM
- PASS : KDC: AS request for root/client.poc.test@POC.TEST

```
# findmnt
TARGET              SOURCE                   FSTYPE OPTIONS
/mnt/autofs/partage //samba.poc.test/partage cifs   rw,relatime,vers=3.1.1,sec=krb5,cruid=0,cache=strict,upcall_target=app,username=root/client.poc.test@POC.TEST,uid=1000,forceuid,gid=1000,forcegid,addr=10.0.3.13,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,reparse=nfs,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1,closetimeo=1
```


### 6.3 Compte de service `svc-partage`, ticket entretenu par systemd

Quand on préfère un compte de service au principal de la machine : un service
oneshot renouvelle le ticket, un timer le relance.

`/etc/systemd/system/krb5-svc-partage.service` :

```
[Unit]
Description=Fetch the Kerberos ticket of svc-partage from its keytab
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=KRB5CCNAME=FILE:/tmp/krb5cc_0
ExecStart=/usr/bin/kinit -k -t /etc/krb5/svc-partage.keytab svc-partage@POC.TEST
```


`/etc/systemd/system/krb5-svc-partage.timer` :

```
[Unit]
Description=Keep the ticket of svc-partage fresh

[Timer]
OnBootSec=10s
OnUnitActiveSec=30min
AccuracySec=1s

[Install]
WantedBy=timers.target
```


Résultat, KDC MIT :

- PASS : mounted without any human kinit
- PASS : findmnt: sec=krb5
- PASS : smbd: Successful AuthZ [SMB2,krb5] as partage (map of svc-partage)
- PASS : smbd: no NTLM
- PASS : KDC: AS request for svc-partage

```
# klist of /tmp/krb5cc_0
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: svc-partage@POC.TEST

Valid starting     Expires            Service principal
11/26/26 16:07:51  11/27/26 02:07:51  krbtgt/POC.TEST@POC.TEST
	renew until 11/27/26 16:07:51
```

```
# findmnt
TARGET      SOURCE                   FSTYPE OPTIONS
/mnt/direct //samba.poc.test/partage cifs   rw,relatime,vers=3.1.1,sec=krb5,cruid=0,cache=strict,upcall_target=app,username=root,uid=1000,forceuid,gid=1000,forcegid,addr=10.0.3.13,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,reparse=nfs,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1,closetimeo=1
```


Résultat, KDC Heimdal :

- PASS : mounted without any human kinit
- PASS : findmnt: sec=krb5
- PASS : smbd: Successful AuthZ [SMB2,krb5] as partage (map of svc-partage)
- PASS : smbd: no NTLM
- PASS : KDC: AS request for svc-partage


### 6.4 Plusieurs utilisateurs : `multiuser,sec=krb5`

Avec `multiuser`, chaque utilisateur Unix accède au partage avec **son**
ticket. `alice` (uid 2001) obtient son ticket d'un keytab personnel
(`kinit -k -t /etc/krb5/alice.keytab`), `bob` (uid 2002) d'`pam_krb5` à la
connexion `ssh`. `libpam-krb5` s'inscrit dans `common-auth`, `common-account`,
`common-password` et `common-session` avec `minimum_uid=1000` (installation du
paquet, `pam-auth-update`) ; `sshd` a `UsePAM yes`.

Piège : lors du montage `multiuser`, le noyau fait une seconde ouverture de
session pour l'uid 0. Sans ticket pour root, `cifs.upcall` échoue (« No Kerberos
credentials available ») et le montage donne l'erreur 13. Root obtient donc
d'abord son ticket du keytab de la machine
(`kinit -k -t /etc/krb5.keytab root/client.poc.test@POC.TEST`).

Autre piège : `chpasswd` passe par PAM, donc par `pam_krb5`, et tenterait de
changer un mot de passe Kerberos ; le banc crée les comptes avec `useradd -p`.

Résultat, KDC MIT :

- PASS : superblock mounted with multiuser and sec=krb5
- PASS : alice (uid 2001) reads secret-alice
- PASS : alice is refused bob's file
- PASS : bob got a ticket from pam_krb5 (klist in the session)
- PASS : bob (uid 2002) reads secret-bob
- PASS : bob is refused alice's file
- PASS : a user with no ticket reads nothing
- PASS : root sees the share as partage and is refused alice-private
- PASS : smbd: Successful AuthZ [SMB2,krb5] for alice, bob and partage
- PASS : smbd: no NTLM

```
# alice reads her file, then bob's
rc=1
2001
secret-alice
cat: /mnt/multi/bob-private/secret.txt: Permission denied
```

```
# bob: ssh login (pam_krb5), reads his file, then alice's
rc=1
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
2002
KRB5CCNAME=FILE:/tmp/krb5cc_2002_Yh8TlJ
Ticket cache: FILE:/tmp/krb5cc_2002_Yh8TlJ
Default principal: bob@POC.TEST

Valid starting     Expires            Service principal
11/26/26 16:07:52  11/27/26 02:07:52  krbtgt/POC.TEST@POC.TEST
	renew until 11/27/26 16:07:52
secret-bob
cat: /mnt/multi/alice-private/secret.txt: Permission denied
```

```
# nobody: no ticket
rc=1
65534
cat: /mnt/multi/public/bonjour.txt: Permission denied
```


Résultat, KDC Heimdal :

- PASS : superblock mounted with multiuser and sec=krb5
- PASS : alice (uid 2001) reads secret-alice
- PASS : alice is refused bob's file
- PASS : bob got a ticket from pam_krb5 (klist in the session)
- PASS : bob (uid 2002) reads secret-bob
- PASS : bob is refused alice's file
- PASS : a user with no ticket reads nothing
- PASS : root sees the share as partage and is refused alice-private
- PASS : smbd: Successful AuthZ [SMB2,krb5] for alice, bob and partage
- PASS : smbd: no NTLM


## 7. Vérifier

Pour chaque cas, quatre preuves :

1. `findmnt -t cifs` montre `sec=krb5` ;
2. `klist` : aucun cache pour la méthode du keytab de la machine (personne n'a
   lancé `kinit`) ;
3. le journal de `smbd` contient `Successful AuthZ: [SMB2,krb5]` et aucune
   ligne NTLMSSP ;
4. le journal du KDC nomme le principal qui a demandé le ticket.

## 8. Cas négatifs

### 8.1 Montage par adresse IP : pas de repli NTLM

Avec `sec=krb5`, le principal de service est `cifs/<hôte saisi>` : par IP, le
KDC répond `LOOKING_UP_SERVER` et le montage échoue (`mount error(126):
Required key not available`). Le serveur, lui, **accepterait** NTLM : le
contrôle positif le montre, avec `Successful AuthZ: [SMB2,NTLMSSP]`. Il n'y a
donc pas de repli silencieux vers NTLM.

- PASS : sec=krb5 by IP is refused
- PASS : the KDC does not know cifs/10.0.3.13
- PASS : smbd: no authorization and no NTLM exchange
- PASS : control: the same server accepts NTLMSSP when the client asks for it

```
# sec=krb5 by IP (the server ACCEPTS NTLMv2 for this test)
rc=32
mount error(126): Required key not available
Refer to the mount.cifs(8) manual page (e.g. man mount.cifs) and kernel log messages (dmesg)
```

```
# control: sec=ntlmssp by IP with a password (proves the server WOULD accept NTLM)
rc=0 
  Successful AuthZ: [SMB2,NTLMSSP] user [SAMBA]\[partage] [S-1-5-21-1336209348-4248724079-4267077521-1000] at [Thu, 26 Nov 2026 16:07:54.548506 UTC] Remote host [ipv4:10.0.3.1:51788] local host [ipv4:10.0.3.13:445]
```


Heimdal :

- PASS : sec=krb5 by IP is refused
- PASS : the KDC does not know cifs/10.0.3.13
- PASS : smbd: no authorization and no NTLM exchange
- PASS : control: the same server accepts NTLMSSP when the client asks for it


### 8.2 Horloge décalée de plus de 5 minutes

+4 minutes : le montage réussit. +10 minutes avec le `krb5.conf` installé :
**il réussit aussi**, parce que libkrb5 se resynchronise sur l'heure du KDC
(`kdc_timesync`, activé par défaut). Pour observer le refus, on désactive la
resynchronisation (`kdc_timesync = 0`) :

```
[libdefaults]
  default_realm = POC.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  kdc_timesync = 0
  udp_preference_limit = 1
  default_ccache_name = FILE:/tmp/krb5cc_%{uid}

[realms]
  POC.TEST = {
    kdc = kdc.poc.test
    admin_server = kdc.poc.test
  }

[domain_realm]
  .poc.test = POC.TEST
  poc.test = POC.TEST
```


Le montage est alors refusé (`krb5_get_init_creds_keytab: -1765328236`,
`KRB5_KDCREP_SKEW`, « Clock skew too great in KDC reply »).

- PASS : +4 minutes: mounted
- PASS : +10 minutes, default krb5.conf: mounted anyway (libkrb5 resynchronises on the KDC's time)
- PASS : +10 minutes, kdc_timesync = 0: refused
- PASS : the refusal is a clock skew (cifs.upcall: krb5_get_init_creds_keytab -1765328236 = KRB5_KDCREP_SKEW)
- PASS : smbd: no authorization, no NTLM

```
# +10 minutes, kdc_timesync = 0 (outside the tolerance)
rc=32 mount error(126): Required key not available
Refer to the mount.cifs(8) manual page (e.g. man mount.cifs) and kernel log messages (dmesg)
```

```
# same clock, kinit: the text of that code
kinit: Clock skew too great in KDC reply while getting initial credentials
```


Heimdal :

- PASS : +4 minutes: mounted
- PASS : +10 minutes, default krb5.conf: mounted anyway (libkrb5 resynchronises on the KDC's time)
- PASS : +10 minutes, kdc_timesync = 0: refused
- PASS : the refusal is a clock skew (cifs.upcall: krb5_get_init_creds_keytab -1765328236 = KRB5_KDCREP_SKEW)
- PASS : smbd: no authorization, no NTLM


### 8.3 Ticket de 3 minutes : réacquisition

Les durées de vie sont ramenées à 3 minutes (`modprinc -maxlife` pour MIT).
Après 200 secondes, le ticket du compte de service a été renouvelé par le
timer, celui d'`alice` (sans timer) a expiré. On redémarre `smbd` : les
montages de la machine et du compte de service se reconnectent, le contrôle
`alice` sans timer **ne se reconnecte pas**.

Remarque mesurée : le montage du keytab de la machine et celui du compte de
service partagent la session noyau (même serveur, même `cruid`), de sorte que la
reconnexion du premier n'a pas produit de requête AS pour
`root/client.poc.test`.

- PASS : mounted /mnt/n3a
- PASS : mounted /mnt/n3b
- PASS : mounted /mnt/n3c
- PASS : machine keytab: the mount survives the expiry
- PASS : service account: the mount survives the expiry thanks to the timer
- PASS : control, no timer: reconnect fails with the expired ticket

```
# t0+200s: ccache of the service account (the timer renewed it)
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: svc-partage@POC.TEST

Valid starting     Expires            Service principal
11/26/26 16:11:01  11/26/26 16:14:01  krbtgt/POC.TEST@POC.TEST
	renew until 11/27/26 16:11:01
```

```
# t0+200s: ccache of alice (expired, nobody renews it)
Ticket cache: FILE:/tmp/krb5cc_2001
Default principal: alice@POC.TEST

Valid starting     Expires            Service principal
11/26/26 16:08:00  11/26/26 16:11:00  krbtgt/POC.TEST@POC.TEST
	renew until 11/27/26 16:08:00
11/26/26 16:08:00  11/26/26 16:11:00  cifs/samba.poc.test@POC.TEST
	renew until 11/27/26 16:08:00
```

```
# smbd restarted: /mnt/n3c, alice, no timer (control)
ls: cannot access '/mnt/n3c': Required key not available
```


Heimdal :

- PASS : mounted /mnt/n3a
- PASS : mounted /mnt/n3b
- PASS : mounted /mnt/n3c
- PASS : machine keytab: the mount survives the expiry
- PASS : service account: the mount survives the expiry thanks to the timer
- PASS : control, no timer: reconnect fails with the expired ticket


### 8.4 Keytab en mode 0644

Un keytab lisible par tous est un secret de la machine lisible par tous :
n'importe quel utilisateur local obtient un ticket de la machine.

- PASS : Kerberos does not check the mode: the mount works with 0644
- PASS : 0644: any local user gets the machine's ticket
- PASS : 0600: the same user is refused

```
# 0644: alice (uid 2001) runs kinit -k -t /etc/krb5.keytab
Ticket cache: FILE:/tmp/krb5cc_2001
Default principal: root/client.poc.test@POC.TEST

Valid starting     Expires            Service principal
11/26/26 16:07:57  11/27/26 02:07:57  krbtgt/POC.TEST@POC.TEST
	renew until 11/27/26 16:07:57
```

```
# 0600: the same command
rc=1 kinit: Permission denied while getting initial credentials
```


Heimdal :

- PASS : Kerberos does not check the mode: the mount works with 0644
- PASS : 0644: any local user gets the machine's ticket
- PASS : 0600: the same user is refused


## 9. Tableau des résultats

| Cas | Description | MIT | Heimdal |
|-----|-------------|-----|---------|
| U  | Samba username map: does a principal with a slash match, quoted or not | PASS | PASS |
| A1 | machine keytab, /etc/fstab line with x-systemd.automount | PASS | PASS |
| A2 | machine keytab, autofs | PASS | PASS |
| A3 | machine keytab, but no username= option: which principal does cifs.upcall try | PASS | PASS |
| B  | service account svc-partage, ticket kept by a systemd service and timer | PASS | PASS |
| C  | multiuser,sec=krb5: alice (per-user keytab), bob (pam_krb5 over ssh), nobody | PASS | PASS |
| N1 | negative: mount by IP address, no NTLM fallback | PASS | PASS |
| N2 | negative: client clock ahead of the KDC (limit 5 minutes) | PASS | PASS |
| N3 | ticket lifetime of 3 minutes: re-acquisition at reconnect | PASS | PASS |
| N4 | negative: keytab with mode 0644 | PASS | PASS |

## 10. Pièges rencontrés

* **`username=`** : sans lui, `cifs.upcall` essaie `root@REALM`, pas le
  principal de la machine.
* **`username map`** : clé `WORKGROUP\root/client.poc.test` ; sans le groupe de
  travail ou avec `@REALM`, erreur 13.
* **Montage par IP** : échoue, pas de repli NTLM.
* **Horloge** : `kdc_timesync` masque un décalage ; code `-1765328236` quand il
  est coupé.
* **Durée de vie** : un ticket sans timer expire, la reconnexion échoue.
* **Keytab en 0644** : tout utilisateur local peut s'authentifier comme la
  machine.
* **`log level`** : le KDC MIT de Debian journalise dans journald, pas dans le
  fichier du `[logging]`.
* **`ktadd`** change la clé, donc le mot de passe, du principal.
* **`chpasswd`** sous `pam_krb5` tente de changer le mot de passe Kerberos.
* **`multiuser`** : root doit avoir un ticket avant le montage.

## 11. Sécurité

* Le keytab `/etc/krb5.keytab` **est le secret de la machine** : qui le lit
  est la machine. Mode 0600, propriétaire root, jamais dans une sauvegarde
  non chiffrée, jamais dans un dépôt.
* Dans un LXC, il n'y a pas de TPM : le keytab repose sur le disque. Protéger le
  stockage de l'hôte Proxmox (chiffrement du volume) et limiter l'accès à
  `pct pull` / `pct enter`.
* Un principal par machine (`root/<fqdn>`), et non un principal partagé ; le
  compte de service `svc-partage` n'a que les droits du partage.
* Le serveur Samba doit refuser NTLM pour que le repli silencieux soit
  impossible (ici, le contrôle N1 l'accepte volontairement pour prouver que
  le refus vient de Kerberos).
* Ne jamais mettre de mot de passe dans une ligne `fstab` ou une unité systemd.
