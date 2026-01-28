#include <openssl/ssl.h>
#include <lean/lean.h>

int lean_f() {
    return 42;
}


void t() {
    // BIO *ssl = BIO_new(BIO_f_ssl());
    // BIO *conn = BIO_new(BIO_s_connect());
    // BIO* bio = BIO_push(ssl, conn);
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *ssl = SSL_new(ctx);
}
