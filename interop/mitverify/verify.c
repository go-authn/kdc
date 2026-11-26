/* SPDX-License-Identifier: BSD-3-Clause
 *
 * An independent verifier of the PAC go-authn/kdc issues: MIT's own code, not
 * ours. It decodes a service ticket, decrypts it with the service key, and
 * runs krb5_kdc_verify_ticket (server 6, KDC 7, ticket 16 and full 19
 * signatures, over the ticket as MIT recodes it) and krb5_pac_verify
 * (CLIENT_INFO against the client and the ticket's authtime).
 *
 *   verify TICKET_HEX SERVICE_KEY_HEX KRBTGT_KEY_HEX CLIENT SERVER
 *
 * Keys are AES-256 (etype 18). Prints one line per PAC buffer type, then "OK".
 * Exit 0 only when every check passed.
 */
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

krb5_error_code krb5_decrypt_tkt_part(krb5_context, const krb5_keyblock *,
                                      krb5_ticket *);
krb5_error_code krb5_kdc_verify_ticket(krb5_context, const krb5_enc_tkt_part *,
                                       krb5_const_principal,
                                       const krb5_keyblock *,
                                       const krb5_keyblock *, krb5_pac *);

static unsigned char *unhex(const char *s, size_t *n)
{
    size_t len = strlen(s), i;
    unsigned char *b = malloc(len / 2 + 1);
    if (len % 2 != 0 || b == NULL)
        return NULL;
    for (i = 0; i < len / 2; i++) {
        unsigned int v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1)
            return NULL;
        b[i] = (unsigned char)v;
    }
    *n = len / 2;
    return b;
}

static void die(krb5_context ctx, krb5_error_code ret, const char *what)
{
    const char *m = ctx ? krb5_get_error_message(ctx, ret) : "";
    fprintf(stderr, "FAIL %s: %d %s\n", what, (int)ret, m);
    exit(1);
}

int main(int argc, char **argv)
{
    krb5_context ctx;
    krb5_error_code ret;
    krb5_ticket *tkt;
    krb5_data td;
    krb5_keyblock svc, tgt;
    krb5_principal cp, sp;
    krb5_pac pac;
    size_t n, i;
    uint32_t *types;
    unsigned char *tb, *sk, *tk;
    size_t tn, skn, tkn;

    if (argc != 6) {
        fprintf(stderr, "usage: verify TICKET SVCKEY TGTKEY CLIENT SERVER\n");
        return 2;
    }
    tb = unhex(argv[1], &tn);
    sk = unhex(argv[2], &skn);
    tk = unhex(argv[3], &tkn);
    if (!tb || !sk || !tk || skn != 32 || tkn != 32) {
        fprintf(stderr, "FAIL bad hex input\n");
        return 2;
    }
    ret = krb5_init_context(&ctx);
    if (ret)
        die(NULL, ret, "krb5_init_context");
    td.magic = KV5M_DATA;
    td.length = (unsigned int)tn;
    td.data = (char *)tb;
    ret = krb5_decode_ticket(&td, &tkt);
    if (ret)
        die(ctx, ret, "krb5_decode_ticket");
    svc.magic = KV5M_KEYBLOCK;
    svc.enctype = 18;
    svc.length = 32;
    svc.contents = sk;
    tgt = svc;
    tgt.contents = tk;
    ret = krb5_decrypt_tkt_part(ctx, &svc, tkt);
    if (ret)
        die(ctx, ret, "krb5_decrypt_tkt_part");
    ret = krb5_parse_name(ctx, argv[4], &cp);
    if (ret)
        die(ctx, ret, "client name");
    ret = krb5_parse_name(ctx, argv[5], &sp);
    if (ret)
        die(ctx, ret, "server name");
    ret = krb5_kdc_verify_ticket(ctx, tkt->enc_part2, sp, &svc, &tgt, &pac);
    if (ret)
        die(ctx, ret, "krb5_kdc_verify_ticket");
    if (pac == NULL) {
        fprintf(stderr, "FAIL the ticket carries no PAC\n");
        return 1;
    }
    ret = krb5_pac_get_types(ctx, pac, &n, &types);
    if (ret)
        die(ctx, ret, "krb5_pac_get_types");
    for (i = 0; i < n; i++)
        printf("buffer %u\n", (unsigned)types[i]);
    ret = krb5_pac_verify(ctx, pac, tkt->enc_part2->times.authtime, cp, NULL,
                          NULL);
    if (ret)
        die(ctx, ret, "krb5_pac_verify (CLIENT_INFO)");
    printf("OK\n");
    return 0;
}
