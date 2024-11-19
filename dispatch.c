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
        if (i == (int) (capacity - 1)) {
            // if at capacity, expand the buffer
            old_capacity = capacity;
            capacity *= 2;
            char *new_buf = calloc(capacity, sizeof(char));
            for (unsigned j = 0; j < old_capacity; j++) {
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

    // printf("Proxy received %d bytes: \n\n%s\n\n", i, buf);
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

void generate_certificates(const char *hostname) {
    char command[512];

    // Generate a private key for the hostname
    snprintf(command, sizeof(command), "openssl genpkey -algorithm RSA -out %s.key -pkeyopt rsa_keygen_bits:2048", hostname);
    system(command);

    // Generate a CSR using the private key
    snprintf(command, sizeof(command), "openssl req -new -key %s.key -out %s.csr -subj \"/CN=%s\"", hostname, hostname, hostname);
    system(command);

    // Generate the certificate signed by CA (using ca.key and ca.crt)
    snprintf(command, sizeof(command), "openssl x509 -req -in %s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out %s.crt -days 365 -sha256", hostname, hostname);
    system(command);

    // Clean up CSR file after signing
    snprintf(command, sizeof(command), "rm %s.csr", hostname);
    system(command);

    printf("Generated %s.key and %s.crt signed by CA.\n\n\n\n", hostname, hostname);
}

void configure_ssl_context(SSL_CTX *ctx, char *hostname) {
    generate_certificates(hostname);
    
    // Load the root CA certificate (ca.crt)
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the domain certificate (domain.crt) and private key (domain.key)
    char cert_file[256];
    char key_file[256];

    snprintf(cert_file, sizeof(cert_file), "%s.crt", hostname);
    snprintf(key_file, sizeof(key_file), "%s.key", hostname);

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
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

    nbytes = read(fd, buffer, BUFFER_SIZE - 1);
    if (nbytes <= 0) {
        //figure out a way to tell the proxy to close the socket with this client
        assert(false);
    }

    buffer[nbytes] = '\0';

    // check if the request is a connect request
    // Step 2: Check if it’s a CONNECT request
    if (strncmp(buffer, "CONNECT", 7) == 0) {
        char *hostname = strtok(buffer + 8, ":");
        
        SSL_CTX *ctx;
        initialize_openssl();
        ctx = create_ssl_context();
        configure_ssl_context(ctx, hostname);
        
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);

        Context_T *new_context = malloc(sizeof(Context_T));
        assert(new_context != NULL);

        new_context->filedes = fd;
        new_context->ssl = ssl;
        new_context->hostname = malloc(strlen(hostname) + 1);
        strcpy(new_context->hostname, hostname);
        new_context->port = atoi(strtok(NULL, " "));

        // Step 3: Send a 200 Connection established response to the client
        const char *connect_response = "HTTP/1.1 200 Connection established\r\n\r\n";
        write(fd, connect_response, strlen(connect_response));

        printf("Trying to establish SSL connection\n");

        // Step 4: Perform SSL handshake with the client after the CONNECT response
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(fd);
            return;
        }

        //HERE
        assert(new_context != NULL);
        append(front, new_context);

        // SSL connection is now established with the client
        // You can now read/write encrypted data with SSL_read and SSL_write
        // Forward requests to the actual server as needed
        printf("SSL connection established with client.\n");
    } else {
        error("Not a CONNECT request\n");
        // If it’s not a CONNECT request, handle it differently or close the connection
        // const char *error_response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        // TODO: need to handle this properly
        // SSL_write(ssl, error_response, strlen(error_response));
    }
}

client_request *read_new_client_request(int fd, Node **ssl_contexts, Context_T *curr_context)
{
    if (curr_context == NULL) {
        /* No SSL Context associated with this file descriptor */

        // read HTTP CONNECT (should be a connect)
        // setup SSL connection, adds to FD -> SSL mapping
        printf("No existing SSL context\n");
        handle_connect_request(fd, ssl_contexts);
        return NULL;
    }

    /* Existing SSL Context associated with this file descriptor */
    /* Ready to read client request */

    client_request *request = malloc(sizeof(client_request));
    assert(request != NULL);

    char buffer[BUFFER_SIZE];
    int n;
    n = SSL_read(curr_context->ssl, buffer, BUFFER_SIZE - 1);
    if (n < 0) {
        // Only here should a client get disconnected
        request->filedes = -1;
        request->req_type = 0;
        request->request_complete = false;
        request->request_data_size = 0;
        request->request_string = NULL;
        return request;
    }

    if (n == 0) {
        printf("Client closed connection\n");
        return NULL;
    }

    buffer[n] = '\0';



    // REMEMBER: buffer[buffer_length] is the null terminator
    if (strncmp(buffer, "GET", 3) == 0) {
        request->req_type = GET_REQUEST;
        request->request_data_size = 0;
    } else if (strncmp(buffer, "POST", 4) == 0) {
        request->req_type = POST_REQUEST;
        int size = get_post_request_data_size(request->request_string);
        request->request_data_size = size;
    } else {
        printf("Unknown request type\n");
        request->req_type = 'U';
        request->request_data_size = 0;
        error("Unknown request type\n");
    }

    request->filedes = fd;
    request->request_string = strdup(buffer);
    request->request_complete = false;

    return request;
}

int get_post_request_data_size(char *buffer) {
    // Find the size of the request data
    char *content_length_ptr = get_content_length_ptr(buffer);

    if (content_length_ptr != NULL) {
        return atoi(content_length_ptr + 16);
    } else if (strstr(buffer, "\r\n\r\n") != NULL) {
        return 0;
    } else {
        return -1;
    }
}

char *get_content_length_ptr(char *str) {
    char *content_length = strstr(str, "Content-Length: ");
    if (content_length == NULL) {
        content_length = strstr(str, "content-length: ");
    }
    if (content_length == NULL) {
        content_length = strstr(str, "Content-length: ");
    }
    if (content_length == NULL) {
        content_length = strstr(str, "content-Length: ");
    }
    if (content_length == NULL) {
        content_length = strstr(str, "CONTENT-LENGTH: ");
    }
    return content_length;
}

void read_existing_incomplete_client_request(client_request **incomplete_request, Context_T *curr_context) {    
    char buffer[BUFFER_SIZE];
    int n;
    n = SSL_read(curr_context->ssl, buffer, BUFFER_SIZE - 1);
    buffer[n] = '\0';

    // Add the new data to the existing request
    char *new_request_string = malloc(strlen((*incomplete_request)->request_string) + n + 1);
    strcpy(new_request_string, (*incomplete_request)->request_string);
    strcat(new_request_string, buffer);
    free((*incomplete_request)->request_string);
    (*incomplete_request)->request_string = new_request_string;

    // NOTE: req_is_complete() will check to see if the request is complete
    if ((*incomplete_request)->req_type == POST_REQUEST) {
        // if ((*incomplete_request)->request_data_size == -1)
        assert((*incomplete_request)->request_data_size == -1);
        int size = get_post_request_data_size((*incomplete_request)->request_string);
        (*incomplete_request)->request_data_size = size;
    }
}

bool req_is_complete(client_request *req) {
    if (req == NULL) {
        return false;
    }

    if (req->req_type == GET_REQUEST) {
        return strstr(req->request_string, "\r\n\r\n") != NULL;
    } 
    
    else if (req->req_type == POST_REQUEST) {
        if (strstr(req->request_string, "\r\n\r\n") == NULL) {
            return false;
        }

        return strlen(req->request_string) - (strstr(req->request_string, "\r\n\r\n") - req->request_string) >= (unsigned) req->request_data_size;
    }

    return false;
}

void send_request_to_cache(client_request *req, int cache_fd, int port, struct sockaddr_un *cache_server_addr, socklen_t cache_server_len) {
    char header[256];
    snprintf(header, sizeof(header), "\r\nX-Original-Client-Address: %d", req->filedes);

    char *end_of_headers = strstr(req->request_string, "\r\n\r\n");
    if (end_of_headers != NULL) {
        size_t header_length = end_of_headers - req->request_string;
        size_t new_request_length = header_length + strlen(header) + strlen(end_of_headers) + 1;
        char *new_request_string = malloc(new_request_length);

        strncpy(new_request_string, req->request_string, header_length);
        new_request_string[header_length] = '\0';
        strcat(new_request_string, header);
        strcat(new_request_string, end_of_headers);

        free(req->request_string);
        req->request_string = new_request_string;
    }
    else {
        printf("Something went wrong\n");
    }
    
    size_t message_length = strlen(req->request_string);
    size_t write_string_length = sizeof(int) + message_length;

    char *write_string = malloc(write_string_length);
    if (!write_string) {
        perror("Failed to allocate memory");
    }

    // int port_network_order = htonl(port);
    memcpy(write_string, &port, sizeof(int));
    memcpy(write_string + sizeof(int), req->request_string, message_length);

    int n = sendto(cache_fd, write_string, write_string_length, 0, (struct sockaddr *) cache_server_addr, (socklen_t) cache_server_len);
    if (n < 0) {
        error("ERROR writing to cache");
    }
    free(write_string);
}

server_response *read_new_server_response(char *response_string, int fd) {
    server_response *response = malloc(sizeof(server_response));
    assert(response != NULL);

    response->filedes = fd;

    response->response_string = strdup(response_string);
    response->response_complete = false;

    response->header_size = -1;
    response->response_content_length = -1;

    get_response_content_length(&response);

    return response;
}

void get_response_content_length(server_response **response) {
    char *response_string = (*response)->response_string;
    
    // header size
    if ((*response)->header_size == -1) {
        char *header_end = strstr(response_string, "\r\n\r\n");
        if (header_end != NULL) {
            (*response)->header_size = header_end - response_string + 4;
        } else {
            (*response)->header_size = -1;
        }
    }

    // data size
    if ((*response)->response_content_length == -1) {
        char *content_length_ptr = get_content_length_ptr(response_string);

        if (content_length_ptr != NULL) {
            (*response)->response_content_length = atoi(content_length_ptr + 16);
        } else if (strstr(response_string, "\r\n\r\n") != NULL) {
            (*response)->response_content_length = 0;
        } else {
            (*response)->response_content_length = -1;
        }
    }
}

void read_existing_server_response(server_response **existing_response, char *next_part_of_response_string) {

    char *new_response_string = malloc(strlen((*existing_response)->response_string) + strlen(next_part_of_response_string) + 1);

    strcpy(new_response_string, (*existing_response)->response_string);
    strcat(new_response_string, next_part_of_response_string);

    new_response_string[strlen((*existing_response)->response_string) + strlen(next_part_of_response_string)] = '\0';
    free((*existing_response)->response_string);
    (*existing_response)->response_string = new_response_string;

    // printf("Current response length: %lu\n", strlen((*existing_response)->response_string));

    if ((*existing_response)->response_content_length == -1 || (*existing_response)->header_size == -1) {
        get_response_content_length(existing_response);
    }
}


bool server_response_is_complete(server_response *response) {
    if (response->response_content_length == -1) {
        return false;
    }

    if (response->response_content_length == 0) {
        return true;
    }

    // printf("\n\nResponse content length is %d\n", response->response_content_length);
    // printf("Data length: %u\n", response->header_size + response->response_content_length);
    // printf("Response length: %ld\n", strlen(response->response_string));

    return strlen(response->response_string) >= (unsigned) (response->response_content_length + response->header_size);
}

char *read_server_response(int cache_fd, struct sockaddr_un *cache_server_addr, socklen_t *cache_server_len) {
    char buffer[BUFFER_SIZE];
    int n = recvfrom(cache_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) cache_server_addr, (socklen_t *) cache_server_len);
    if (n < 0) {
        error("ERROR reading from server");
    }
    if (n == 0) {
        printf("Server closed connection\n");
    }

    char *response = malloc(n + 1);
    assert(response != NULL);
    strncpy(response, buffer, n);
    response[n] = '\0';

    return response;
}

void respond_to_client(server_response *res, Node *ssl_contexts) {
    char *response = res->response_string;
    int response_size = strlen(response);

    Context_T *curr_context = get_ssl_context(ssl_contexts, res->filedes);
    int n = SSL_write(curr_context->ssl, response, response_size);
    if (n <= 0) {
        ERR_print_errors_fp(stderr); // Print SSL error details
        error("Something bad happened during SSL_write");
    }
}