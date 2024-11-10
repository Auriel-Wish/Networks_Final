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

typedef struct {
    char *buf;
    int size;
} Buffer_T;

void error(char *msg)
{
    perror(msg);
    exit(0);
}

Buffer_T *new_Buffer_T(char *buf, int size)
{
    Buffer_T *buffer = malloc(sizeof(Buffer_T));
    buffer->buf = buf;
    buffer->size = size;

    return buffer;
}

Dispatch_T* new_dispatch()
{
    Dispatch_T *dispatch = malloc(sizeof(Dispatch_T));
    assert(dispatch != NULL);

    dispatch->placeholder = 0;
    dispatch->buffer = NULL;
    dispatch->size = 0;

    return dispatch;
}

void free_dispatch(Dispatch_T **dispatch)
{
    free(*dispatch);
    *dispatch = NULL;
}

Buffer_T *read_get_request(int childfd)
{
    char ch;
    int status;
    int i = 0;
    bool prior_CRLF = false;

    // NOTE: I'm going to allocate the buffer on the heap here.
    // Using calloc to initialize every slot to 0
    char *buf = calloc(BUFFER_SIZE, sizeof(char));
    unsigned long capacity = BUFFER_SIZE;
    unsigned long old_capacity = BUFFER_SIZE;

    // GET requests must be less than BUFFER_SIZE right now
    while (true)
    {
        if (i == capacity - 1) {
            // if at capacity, expand the buffer
            old_capacity = capacity;
            capacity *= 2;
            char *new_buf = calloc(capacity, sizeof(char));
            for (int j = 0; j < old_capacity; j++) {
                new_buf[j] = buf[j];
            }

            free(buf);
            buf = new_buf;
        }

        status = read(childfd, &ch, 1);

        if (status < 0)
            error("ERROR reading from socket");

        buf[i] = ch;
        i++;

        if (ch == '\r')
        {
            status = read(childfd, &ch, 1);
            buf[i] = ch;
            i++;

            if (ch == '\n')
            {
                if (prior_CRLF)
                {
                    // two carriage returns in a row means end of request
                    // printf("\nRequest completed\n");
                    break;
                }

                prior_CRLF = true;
            }
            else
            {
                printf("Bad formatting\n");
            }
        }
        else
        {
            prior_CRLF = false;
        }
    }

    printf("Proxy received %d bytes: \n\n%s\n\n", i, buf);
    Buffer_T *buffer = new_Buffer_T(buf, i);

    return buffer;
}

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

void handle_connect_request(int fd, Node **front)
{
    char buffer[BUFFER_SIZE];
    int nbytes;

    nbytes = read(fd, buffer, sizeof(buffer) - 1);
    if (nbytes <= 0) {
        //figure out a way to tell the proxy to close the socket with this client
        assert(false);
    }

    buffer[nbytes] = '\0';

    printf("Buffer content is:\n\n%s\n\n", buffer);

    // check if the request is a connect request
        // Step 2: Check if it’s a CONNECT request
    if (strncmp(buffer, "CONNECT", 7) == 0) {
        SSL_CTX *ctx;
        initialize_openssl();
        ctx = create_ssl_context();
        configure_ssl_context(ctx);
        
        // do we need the client addr

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);

        Context_T *new_context = malloc(sizeof(Context_T));
        assert(new_context != NULL);
        new_context->ssl = ssl;
        new_context->filedes = fd;

        // Step 3: Send a 200 Connection established response to the client
        const char *connect_response = "HTTP/1.1 200 Connection established\r\n\r\n";
        write(fd, connect_response, strlen(connect_response));

        // Step 4: Perform SSL handshake with the client after the CONNECT response
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(fd);
            return;
        }

        append(front, new_context);

        // SSL connection is now established with the client
        // You can now read/write encrypted data with SSL_read and SSL_write
        // Forward requests to the actual server as needed
        printf("SSL connection established with client.\n");

        // // Example of reading data from the client and forwarding it could go here
        // while ((nbytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        //     buffer[nbytes] = '\0';
        //     printf("Received encrypted data from client: %s\n", buffer);

        //     // Forwarding logic to the destination server goes here
        //     // For example, you could now set up an SSL connection to example.com, 
        //     // forward `buffer` to the server, and relay the response back.
        // }
    } else {
        // If it’s not a CONNECT request, handle it differently or close the connection
        // const char *error_response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        // TODO: need to handle this properly
        assert(false);
        // SSL_write(ssl, error_response, strlen(error_response));
    }
}


HTTPS_REQ_T* read_client_request(int fd, Node **front)
{
    // CHECK if the fd is already associated with a SSL connection
    // Auriel TODO
    HTTPS_REQ_T *request = NULL;

    SSL *curr_context = get_ssl_context(*front, fd);
    if (curr_context != NULL) {
        // handle normal requests
        // TODO: buffer SSL read
        char buffer[BUFFER_SIZE];
        int n;
        n = SSL_read(curr_context, buffer, sizeof(buffer) - 1);
        buffer[n] = '\0';

        request = malloc(sizeof(HTTPS_REQ_T));
        assert(request != NULL);

        //The HTTPS request is currently hardcoded here. Once we successfully can
        //communicate with the client via HTTPS, we will change this
        char *hostname = "google.com";
        char *port = "443";
        char *request_string = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n";

        request->size = strlen(request_string);
        request->hostname = strdup(hostname);
        request->portno = strdup(port);
        request->request_string = strdup(request_string);
    }
    else {
        // if no, read HTTP CONNECT (should be a connect)
        //setup SSL connection, adds to FD -> SSL mapping
        // TODO: This needs to take in a pointer to Auriel's linked list
        handle_connect_request(fd, front);
    }

    // if yes, read HTTPS GET using SSL read (should be a GET)
    return request;
}

void respond_to_client()
{
    printf("Responding to the client\n");
}


/* Old hardcoding 
    This step could be super difficult because we need to pretend to be our
    own SSL certificate. For now, we will keep it simple by hardcoding the
    HTTPS request in the buffer    

    Buffer_T *incoming = read_get_request(fd);
    (void)incoming;


    // if client disconnects, return NULL
    HTTPS_REQ_T *req = malloc(sizeof(HTTPS_REQ_T));
    assert(req != NULL);

    //The HTTPS request is currently hardcoded here. Once we successfully can
    //communicate with the client via HTTPS, we will change this
    char *hostname = "google.com";
    char *port = "443";
    char *request = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n";

    req->size = strlen(request);
    req->hostname = strdup(hostname);
    req->portno = strdup(port);
    req->request = strdup(request);

    return req;
*/