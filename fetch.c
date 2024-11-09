#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "fetch.h"


char* fetch(char *hostname, char *port, char *request) {

    SSL_library_init();                   // Initialize the OpenSSL library
    SSL_load_error_strings();              // Load error strings for diagnostics
    OpenSSL_add_ssl_algorithms();          // Load SSL algorithms

    const SSL_METHOD *method = TLS_client_method();   // Set the TLS method to use
    SSL_CTX *ctx = SSL_CTX_new(method);    // Create an SSL context
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Create a socket and connect to the host
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &res) != 0) {
        perror("getaddrinfo");
        SSL_CTX_free(ctx);
        return NULL;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("socket");
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        perror("connect");
        close(sock);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        return NULL;
    }
    freeaddrinfo(res);

    // Create an SSL object and attach it to the socket
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {          // Perform the SSL/TLS handshake
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Send the HTTP GET request
    if (SSL_write(ssl, request, strlen(request)) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Receive and print the response
    char buffer[4096];
    int bytes;
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes] = '\0';
        printf("%s", buffer);
    }

    // Clean up
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    // should return non-NULL here
    return NULL;
}