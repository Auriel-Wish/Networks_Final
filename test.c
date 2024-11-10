#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_server_method(); // Use the TLS server method
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    // Load the root CA certificate (ca.crt)
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the domain certificate (domain.crt) and private key (domain.key)
    if (SSL_CTX_use_certificate_file(ctx, "example.com.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "example.com.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

int create_socket(int port) {
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void handle_client_connection(int client_sock, SSL_CTX *ctx) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);

    char buffer[1024] = {0};
    int bytes;

    // Step 1: Read the initial request from the client
    bytes = read(client_sock, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        close(client_sock);
        return;
    }

    buffer[bytes] = '\0';
    printf("Received request: %s\n", buffer);

    // Step 2: Check if it’s a CONNECT request
    if (strncmp(buffer, "CONNECT", 7) == 0) {
        // Step 3: Send a 200 Connection established response to the client
        const char *connect_response = "HTTP/1.1 200 Connection established\r\n\r\n";
        write(client_sock, connect_response, strlen(connect_response));

        // Step 4: Perform SSL handshake with the client after the CONNECT response
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_sock);
            return;
        }

        // SSL connection is now established with the client
        // You can now read/write encrypted data with SSL_read and SSL_write
        // Forward requests to the actual server as needed
        printf("SSL connection established with client.\n");

        // Example of reading data from the client and forwarding it could go here
        while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes] = '\0';
            printf("Received encrypted data from client: %s\n", buffer);

            // Forwarding logic to the destination server goes here
            // For example, you could now set up an SSL connection to example.com, 
            // forward `buffer` to the server, and relay the response back.
        }
    } else {
        // If it’s not a CONNECT request, handle it differently or close the connection
        const char *error_response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        SSL_write(ssl, error_response, strlen(error_response));
    }

    // Step 5: Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);
}

int main(int argc, char **argv) {
    int sock;
    SSL_CTX *ctx;

    initialize_openssl();
    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    sock = create_socket(9052);

    // Accept client connections and handle them
    while (1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        handle_client_connection(client, ctx);
    }

    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
