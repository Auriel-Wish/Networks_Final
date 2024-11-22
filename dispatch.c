#include "dispatch.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_server_method(); // Use the TLS server method
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context ");
        ERR_print_errors_fp(stderr);
    }

    return ctx;
}

void generate_certificates(const char *hostname) {
    char command[1024];

    // Generate a private key for the hostname
    snprintf(command, sizeof(command), "openssl genpkey -algorithm RSA -out %s.key -pkeyopt rsa_keygen_bits:2048 > /dev/null 2>&1", hostname);
    system(command);

    // Create a temporary OpenSSL configuration file to specify SAN, Key Usage, and EKU for the CSR
    snprintf(command, sizeof(command), 
        "echo \"[ req ]\n"
        "default_bits = 2048\n"
        "distinguished_name = req_distinguished_name\n"
        "req_extensions = v3_req\n"
        "[ req_distinguished_name ]\n"
        "[ v3_req ]\n"
        "subjectAltName = @alt_names\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "[ alt_names ]\n"
        "DNS.1 = %s\" > %s.cnf", 
        hostname, hostname);
    system(command);

    // Generate a CSR using the private key and include SAN, Key Usage, and EKU from the configuration
    snprintf(command, sizeof(command), "openssl req -new -key %s.key -out %s.csr -subj \"/CN=%s\" -config %s.cnf > /dev/null 2>&1", hostname, hostname, hostname, hostname);
    system(command);

    // Generate the certificate signed by the CA (using Networks_Final_Project.key and Networks_Final_Project.crt)
    snprintf(command, sizeof(command), "openssl x509 -req -in %s.csr -CA Networks_Final_Project.crt -CAkey Networks_Final_Project.key -CAcreateserial -out %s.crt -days 365 -sha256 -extfile %s.cnf -extensions v3_req > /dev/null 2>&1", hostname, hostname, hostname);
    system(command);

    // Clean up CSR and temporary configuration file after signing
    snprintf(command, sizeof(command), "rm %s.csr %s.cnf > /dev/null 2>&1", hostname, hostname);
    system(command);

    printf("Generated %s.key and %s.crt signed by Networks_Final_Project with SAN, Key Usage, and EKU.\n", hostname, hostname);
}

void configure_ssl_context(SSL_CTX *ctx, char *hostname) {
    generate_certificates(hostname);
    
    // Load the root CA certificate (Networks_Final_Project.crt)
    if (SSL_CTX_load_verify_locations(ctx, "Networks_Final_Project.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
    }

    // Load the domain certificate (domain.crt) and private key (domain.key)
    char cert_file[256];
    char key_file[256];

    snprintf(cert_file, sizeof(cert_file), "%s.crt", hostname);
    snprintf(key_file, sizeof(key_file), "%s.key", hostname);

    // We want some way to clean up the files that were written after use.

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
    }
}

void open_new_conn_to_server(char *hostname, int port, Context_T **curr_context) {
    printf("\nConnecting to %s:%d..", hostname, port);

    // Use the TLS client method
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    // Set SSL context options
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Unable to create socket");
        return;
    }

    struct hostent *server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        close(server_fd);
        return;
    }

    struct sockaddr_in server_addr;
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(port);

    if (connect(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("ERROR connecting");
        close(server_fd);
        return;
    }

    // Create an SSL connection
    SSL *server_ssl = SSL_new(ctx);
    if (!server_ssl) {
        printf("SSL creation failed\n");
    }

    SSL_set_fd(server_ssl, server_fd);

    // Set the SNI hostname
    if (!SSL_set_tlsext_host_name(server_ssl, hostname)) {
        fprintf(stderr, "Error setting SNI hostname.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(server_ssl);
        close(server_fd);
        return;
    }

    // Perform the TLS handshake
    if (SSL_connect(server_ssl) <= 0) {
        printf("SSL connection failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(server_ssl);
        close(server_fd);
        return;
    }

    (*curr_context)->server_fd = server_fd;
    (*curr_context)->server_ssl = server_ssl;
    printf("CONNECTED\n");
}

bool handle_connect_request(int fd, Node **ssl_contexts, fd_set *active_read_fd_set, int *max_fd) {
    // Step 1: Read the connect request
    char buffer[BUFFER_SIZE];
    int nbytes;

    nbytes = read(fd, buffer, BUFFER_SIZE - 1);
    if (nbytes <= 0) {
        return false;
    }

    if (nbytes == (BUFFER_SIZE - 1)) {
        fprintf(stderr, "Buffer was too small to handle connect\n");
        assert(false);
    }

    buffer[nbytes] = '\0'; //Null-terminating the buffer

    // Step 2: Check if it’s a CONNECT request
    if (strncmp(buffer, "CONNECT", 7) == 0) {
        char *hostname = strtok(buffer + 8, ":");
        
        SSL_CTX *ctx;
        ctx = create_ssl_context();
        configure_ssl_context(ctx, hostname);
        
        SSL *client_ssl = SSL_new(ctx);
        SSL_set_fd(client_ssl, fd);

        Context_T *new_context = malloc(sizeof(Context_T));
        assert(new_context != NULL);

        new_context->client_fd = fd;
        new_context->client_ssl = client_ssl;

        new_context->hostname = calloc(strlen(hostname) + 1, sizeof(char));
        assert(new_context->hostname != NULL);
        strcpy(new_context->hostname, hostname);

        new_context->server_fd = -1;
        new_context->server_ssl = NULL;

        // Step 3: Send a 200 Connection established response to the client
        const char *connect_response = "HTTP/1.1 200 Connection established\r\n\r\n";
        write(fd, connect_response, strlen(connect_response));

        // Step 4: Perform SSL handshake with the client after the CONNECT response
        if (SSL_accept(client_ssl) <= 0) {
            printf("\nSSL handshake failed\n");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(client_ssl);
            SSL_free(client_ssl);
            close(fd);
            return false;
        }

        printf("\nSSL handshake with client successful\n");

        int port = atoi(strtok(NULL, " "));
        open_new_conn_to_server(hostname, port, &new_context);

        assert(new_context != NULL);
        append(ssl_contexts, new_context);

        FD_SET(new_context->server_fd, active_read_fd_set);
        set_max_fd(new_context->server_fd, max_fd);

        return true;
    } 
    
    else {
        printf("Not a CONNECT request\n");
        
        for (int i = 0; i < nbytes; i++) {
            putchar(buffer[i]);
        }
        return false;
    }
}


bool read_client_request(int client_fd, Node **ssl_contexts, 
    fd_set *active_read_fd_set, int *max_fd, Cache_T *cache) {
    Context_T *curr_context = get_ssl_context_by_client_fd(*ssl_contexts, client_fd);

    (void)cache;
    
    if (curr_context == NULL) {
        /* No SSL Context associated with this file descriptor */

        // read HTTP CONNECT (should be a connect)
        // setup SSL connection, adds to FD -> SSL mapping
        return handle_connect_request(client_fd, ssl_contexts, active_read_fd_set, max_fd);
    }

    // // check the cache to see if the content is present:
    // Cache_Response_T *resp = get_response_from_cache(cache, curr_context->hostname);

    // if (resp != NULL) {
    //     // SSL_write(curr_context->)
    // }
    
    else {
        printf("Reading ONE client request\n");
        char buffer[BUFFER_SIZE + 1];
        int n;

        n = SSL_read(curr_context->client_ssl, buffer, BUFFER_SIZE);
        buffer[n] = '\0';
        
        if (n > 0) {
            n = SSL_write(curr_context->server_ssl, buffer, n);
            if (n == 0) {
                printf("Server closed connection\n");
                return false;
            }
            if (n < 0) {
                printf("Error writing to server\n");
                return false;
            }

            return true;
        } else {
            int ssl_error = SSL_get_error(curr_context->client_ssl, n);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // Need to retry the operation later
                return true; // Keep the connection open
            } else {
                // Handle other errors
                // printf("\nClient FD: %d\n", curr_context->client_fd);
                // printf("SSL_read failed with error code %d\n", ssl_error);
                return false; // Close the connection
            }
        }
    }
}

bool read_server_response(int server_fd, Node **ssl_contexts) {
    Context_T *curr_context = get_ssl_context_by_server_fd(*ssl_contexts, server_fd);
    if (curr_context == NULL) {
        return false;
    }

    // char buffer[BUFFER_SIZE];
    char buffer[BUFFER_SIZE + 1];
    int read_n = SSL_read(curr_context->server_ssl, buffer, BUFFER_SIZE);

    fprintf(stderr, "READING SERVER RESPONSE: %d bytes...", read_n);

    

    if (read_n > 0) {
        buffer[read_n] = '\0';

        /*
        printf("\n\nServer response: %s\n", buffer);
        if (curr_context->response_header_length == -1) {
            curr_context->response_header_length = get_header_length(buffer, n);
            if (curr_context->response_header_length != -1) {
                curr_context->response_content_length = get_content_length(buffer, n);
            }
        }
        */
        
        int total_written = 0;
        while (total_written < read_n) {
            int write_n = SSL_write(curr_context->client_ssl, buffer + total_written, read_n - total_written);
            if (write_n <= 0) {
                printf("Error writing to client\n");
                return false;
            }
            total_written += write_n;
        }

        fprintf(stderr, "DONE\n");

        return true;
    }  
    
    else {
        fprintf(stderr, "ERROR\n");

        int ssl_error = SSL_get_error(curr_context->server_ssl, read_n);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // Need to retry the operation later
            return true; // Keep the connection open
        } else {
            // Handle other errors
            // printf("\nClient FD: %d\n", curr_context->server_fd);
            // printf("SSL_read failed with error code %d\n", ssl_error);
            return false; // Close the connection
        }
    }
}

int client_or_server_fd(Node *ssl_contexts, int fd) {
    if (get_ssl_context_by_client_fd(ssl_contexts, fd) != NULL) {
        return CLIENT_FD;
    } else if (get_ssl_context_by_server_fd(ssl_contexts, fd) != NULL) {
        return SERVER_FD;
    } else {
        return NO_FD_ASSOCIATION;
    }
}

void set_max_fd(int new_fd, int *max_fd) {
    if (new_fd + 1 > *max_fd) {
        *max_fd = new_fd + 1;
    }
}




// int get_header_length(char *buff) {
//     char *header_end = strstr(buff, "\r\n\r\n");
//     if (header_end == NULL) {
//         return -1;
//     }

//     return header_end - buff + 4;
// }

// int get_content_length(char *buff) {
//     // Find the size of the request data
//     char *content_length_ptr = get_content_length_ptr(buff);

//     if (content_length_ptr != NULL) {
//         return atoi(content_length_ptr + 16);
//     } else {
//         return 0;
//     }
// }

// char *get_content_length_ptr(char *str) {
//     assert(str != NULL);
//     char *content_length = strstr(str, "Content-Length: ");
//     if (content_length == NULL) {
//         content_length = strstr(str, "content-length: ");
//     }

//     if (content_length == NULL) {
//         content_length = strstr(str, "Content-length: ");
//     }

//     if (content_length == NULL) {
//         content_length = strstr(str, "content-Length: ");
//     }

//     if (content_length == NULL) {
//         content_length = strstr(str, "CONTENT-LENGTH: ");
//     }

//     return content_length;
// }