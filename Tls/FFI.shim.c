#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <stddef.h>
#include <string.h>

int lean_f() {
    return 42;
}


void t() {
    // BIO *ssl = BIO_new(BIO_f_ssl());
    // // BIO *conn = BIO_new(BIO_s_connect());
    // // BIO* bio = BIO_push(ssl, conn);
    // BIO *b1, *b2;
    // // BIO_new_bio_pair(&b1, 0, &b2, 0);
    // // BIO_new_ssl()
    // SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    // SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);
    // // SSL *ssl = SSL_new(ctx);
    
    // BIO *net_in, *net_out;  // the two ends of the BIO pair

    // BIO_new_bio_pair(&net_in, 0, &net_out, 0);                  // convenience :contentReference[oaicite:2]{index=2}

    // BIO *tls = BIO_new_ssl(ctx, 1 /*client*/);                  // SSL filter BIO :contentReference[oaicite:4]{index=4}
    // tls = BIO_push(tls, net_in);                                // tls <-> net_in transport :contentReference[oaicite:5]{index=5}

    // // Configure SNI / hostname verification on the underlying SSL*
    // SSL *ssl = NULL;
    // BIO_get_ssl(tls, &ssl);
    // BIO_write
    // BIO_meth_new()
    // BIO_meth_set_read_ex()
}
