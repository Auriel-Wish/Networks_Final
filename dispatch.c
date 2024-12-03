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

#include <zlib.h>
#define DECOMPRESSED_BUFFER_SIZE 8192 // Adjust this as needed
#define CHUNK 16384


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

    // printf("Generated %s.key and %s.crt signed by Networks_Final_Project with SAN, Key Usage, and EKU.\n", hostname, hostname);
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
    // printf("\nConnecting to %s:%d..", hostname, port);

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
        // printf("SSL connection failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(server_ssl);
        close(server_fd);
        return;
    }

    (*curr_context)->server_fd = server_fd;
    (*curr_context)->server_ssl = server_ssl;

    // printf("CONNECTED\n");
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
            // printf("\nSSL handshake failed\n");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(client_ssl);
            SSL_free(client_ssl);
            close(fd);
            return false;
        }

        // printf("\nSSL handshake with client successful\n");

        int port = atoi(strtok(NULL, " "));
        open_new_conn_to_server(hostname, port, &new_context);

        assert(new_context != NULL);
        append(ssl_contexts, new_context);

        FD_SET(new_context->server_fd, active_read_fd_set);
        set_max_fd(new_context->server_fd, max_fd);

        return true;
    } 
    
    else {
        // printf("Not a CONNECT request\n");
        
        for (int i = 0; i < nbytes; i++) {
            putchar(buffer[i]);
        }
        return false;
    }
}

char *inject_encoding_method(char *buffer, unsigned size) 
{
    (void)buffer;
    (void)size;
    return NULL;
}

bool read_client_request(int client_fd, Node **ssl_contexts, 
    fd_set *active_read_fd_set, int *max_fd, Cache_T *cache, Node **all_messages) {
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
    
    else {
        // printf("Reading ONE client request\n");
        char buffer[BUFFER_SIZE + 1];
        int n;

        n = SSL_read(curr_context->client_ssl, buffer, BUFFER_SIZE);
        
        if (n > 0) {
            message *curr_message = get_message_by_filedes(*all_messages, curr_context->client_fd);
            curr_message = insert_new_data(&curr_message, buffer, curr_context->client_fd, all_messages, n);
            if (curr_message->msg_complete) {
                // Check if "fact-check" appears in the first line of the header
                char *fact_check = strstr(curr_message->header, "fact-check");
                if (fact_check == NULL) {
                    n = SSL_write(curr_context->server_ssl, curr_message->header, curr_message->header_length);
                    if (n <= 0) {
                        return false;
                    }
                    if (curr_message->content_length > 0) {
                        n = SSL_write(curr_context->server_ssl, curr_message->content, curr_message->content_length);
                        if (n <= 0) {
                            return false;
                        }
                        printf("Wrote to server: %s\n", curr_message->content);
                    }
                }
                else {
                    // Send to LLM
                    char *example = "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Content-Length: 35\r\n"
                                    "\r\n"
                                    "{\"factCheck\": \"I will fact check!\"}";
                    n = SSL_write(curr_context->client_ssl, example, strlen(example));
                }
                
                removeNode(all_messages, curr_message);
            }

            // char *accept_encoding = strstr(buffer, "Accept-Encoding: ");
            // if (accept_encoding != NULL) {
            //     char *end_of_line = strstr(accept_encoding, "\r\n");
            //     if (end_of_line != NULL) {
            //         size_t prefix_length = accept_encoding - buffer;
            //         size_t suffix_length = strlen(end_of_line + 2); // +2 to skip \r\n
            //         memmove(accept_encoding, end_of_line + 2, suffix_length);
            //         // snprintf(buffer + prefix_length, BUFFER_SIZE - prefix_length, "Accept-Encoding: gzip\r\n%s", end_of_line + 2);
            //         snprintf(buffer + prefix_length, BUFFER_SIZE - prefix_length, "Accept-Encoding: identity\r\n%s", end_of_line + 2);
            //     }
            // }

            // fprintf(stderr, "Printing out the HEADER\n");

            // n = SSL_write(curr_context->server_ssl, buffer, n);
            // if (n == 0) {
            //     // printf("Server closed connection\n");
            //     return false;
            // }
            // if (n < 0) {
            //     // printf("Error writing to server\n");
            //     return false;
            // }

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

int compress_gzip_message_content(message *msg, unsigned char **compressed, int *compressed_length) {
    z_stream strm;
    unsigned char out[CHUNK];
    int ret;
    int have;
    unsigned char *result = NULL;
    int result_size = 0;

    // Initialize zlib stream
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    // Initialize for GZIP compression
    ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        return ret;
    }

    strm.avail_in = msg->content_length;
    strm.next_in = msg->content;

    do {
        strm.avail_out = CHUNK;
        strm.next_out = out;
        ret = deflate(&strm, Z_FINISH);
        if (ret != Z_STREAM_END && ret != Z_OK && ret != Z_BUF_ERROR) {
            deflateEnd(&strm);
            free(result);
            return ret;
        }
        have = CHUNK - strm.avail_out;
        result = realloc(result, result_size + have);
        if (!result) {
            deflateEnd(&strm);
            return Z_MEM_ERROR;
        }
        memcpy(result + result_size, out, have);
        result_size += have;
    } while (strm.avail_out == 0);

    // Clean up
    deflateEnd(&strm);

    *compressed = result;
    *compressed_length = result_size;
    return Z_OK;
}

void update_message_header_content_length(message *msg, int new_content_length) {
    char *cl_pos = strstr(msg->header, "Content-Length: ");
    if (cl_pos) {
        char *line_end = strstr(cl_pos, "\r\n");
        if (line_end) {
            char new_value[32];
            snprintf(new_value, sizeof(new_value), "Content-Length: %d", new_content_length);
            int new_value_len = strlen(new_value);
            int old_value_len = line_end - cl_pos;
            memmove(cl_pos + new_value_len, cl_pos + old_value_len, msg->header_length - (cl_pos - msg->header) - old_value_len);
            memcpy(cl_pos, new_value, new_value_len);
            msg->header_length += new_value_len - old_value_len;  // Adjust the header length
        }
    }
}

int process_message(message *msg) {
    unsigned char *compressed_content = NULL;
    int compressed_length = 0;

    // Compress the content
    int ret = compress_gzip_message_content(msg, &compressed_content, &compressed_length);
    if (ret != Z_OK) {
        fprintf(stderr, "GZIP compression failed with error code: %d\n", ret);
        return ret;
    }

    // Update Content-Length in the header
    update_message_header_content_length(msg, compressed_length);

    // Replace content with compressed content
    free(msg->content);  // Free the original content
    msg->content = compressed_content;
    msg->content_length = compressed_length;

    return 0;
}


bool decompress(message *m) {
    if (m == NULL || m->content == NULL || m->content_length == 0) {
        fprintf(stderr, "Message is null or content is empty. Cannot decompress.\n");
        return false;
    }

    // Allocate buffer for decompressed data
    size_t decompressed_size = m->content_length * 4; // Estimate a reasonable expansion factor
    unsigned char *decompressed_content = malloc(decompressed_size);
    if (decompressed_content == NULL) {
        fprintf(stderr, "Failed to allocate memory for decompression.\n");
        return false;
    }

    z_stream stream = {0};
    stream.next_in = m->content;
    stream.avail_in = m->content_length;
    stream.next_out = decompressed_content;
    stream.avail_out = decompressed_size;

    // Initialize zlib for gzip decoding
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
        fprintf(stderr, "Failed to initialize zlib for gzip decompression.\n");
        free(decompressed_content);
        return false;
    }

    int result = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);

    if (result == Z_STREAM_END) {
        // Successfully decompressed
        fprintf(stderr, "Decompressed %lu bytes to %lu bytes.\n", (unsigned long)m->content_length, (unsigned long)stream.total_out);

        // Free the original content and replace it with the decompressed content
        free(m->content);
        m->content = decompressed_content;
        m->content_length = stream.total_out;
        return true;
    } else {
        // Decompression failed
        fprintf(stderr, "Decompression failed (error code: %d).\n", result);
        free(decompressed_content);
        return false;
    }
}


bool read_server_response(int server_fd, Node **ssl_contexts, Node **all_messages) {
    Context_T *curr_context = get_ssl_context_by_server_fd(*ssl_contexts, server_fd);
    if (curr_context == NULL) {
        return false;
    }

    char buffer[BUFFER_SIZE];
    // char buffer[BUFFER_SIZE + 1];
    int read_n = SSL_read(curr_context->server_ssl, buffer, BUFFER_SIZE);


    if (read_n > 0) {
        int write_n;

        // buffer[read_n] = '\0';

        // // NOTE: Working version
        // char *header_end = strstr(buffer, "\r\n\r\n");
        // if (header_end != NULL) {
        //     printf("\nFOUND A HEADER\n");
        // } else {
        //     printf("\nFOUND A BODY\n");
        //     decompress_and_print(buffer, read_n);
        // }

        // fprintf(stderr, "READING SERVER RESPONSE:\n");

        // int total_written = 0;
        // while (total_written < read_n) {
        //     int write_n = SSL_write(curr_context->client_ssl, buffer + total_written, read_n - total_written);
        //     if (write_n <= 0) {
        //         // printf("Error writing to client\n");
        //         return false;
        //     }
        //     total_written += write_n;
        // }

        // Experimental Version
        // Needs to differentiate between headers and bodies
        message *curr_message = get_message_by_filedes(*all_messages, curr_context->server_fd);
        curr_message = insert_new_data(&curr_message, buffer, curr_context->server_fd, all_messages, read_n);
        if (curr_message->msg_complete) {
            inject_script_into_html(curr_message);

            if (curr_message->content_type == CHUNKED_ENCODING) {
                update_message_header_no_chunk(curr_message);
            }

            write_n = SSL_write(curr_context->client_ssl, curr_message->header, curr_message->header_length);
            if (write_n <= 0) {
                return false;
            }
            if (curr_message->content_length > 0) {
                write_n = SSL_write(curr_context->client_ssl, curr_message->content, curr_message->content_length);
            }
            if (write_n <= 0) {
                return false;
            }
            removeNode(all_messages, curr_message);
        }

        return true;
    }  
    
    else {
        // fprintf(stderr, "ERROR\n");

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

void update_message_header_no_chunk(message *msg) {
    if (msg == NULL || msg->header == NULL) {
        fprintf(stderr, "Error: message or header is NULL.\n");
        return;
    }

    const char *chunked_encoding = "Transfer-Encoding: chunked\r\n";
    char content_length_header[64];

    // Check if "Transfer-Encoding: chunked" exists in the header
    char *chunked_position = strstr(msg->header, chunked_encoding);
    if (chunked_position == NULL) {
        fprintf(stderr, "Error: 'Transfer-Encoding: chunked' not found in header.\n");
        return;
    }

    // Create the new "Content-Length" header string
    snprintf(content_length_header, sizeof(content_length_header), "Content-Length: %d\r\n", msg->content_length);

    // Calculate new header size
    size_t header_prefix_length = chunked_position - msg->header; // Length of header before "Transfer-Encoding: chunked"
    size_t header_suffix_length = strlen(chunked_position + strlen(chunked_encoding)); // Length of header after "Transfer-Encoding: chunked"
    size_t new_header_length = header_prefix_length + strlen(content_length_header) + header_suffix_length;

    // Allocate memory for the new header
    char *new_header = (char *)malloc(new_header_length + 1);
    if (new_header == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for new header.\n");
        return;
    }

    // Build the new header
    strncpy(new_header, msg->header, header_prefix_length); // Copy part before "Transfer-Encoding: chunked"
    new_header[header_prefix_length] = '\0'; // Null-terminate temporarily
    strcat(new_header, content_length_header); // Append "Content-Length: ..."
    strcat(new_header, chunked_position + strlen(chunked_encoding)); // Append part after "Transfer-Encoding: chunked"

    // Free the old header and assign the new header to msg
    free(msg->header);
    msg->header = new_header;
    msg->header_length = (int)new_header_length;
}

message *insert_new_data(message **msg, char *buffer, int filedes, Node **all_messages, int n) {
    message *curr_message = *msg;
    if (curr_message == NULL) {
        curr_message = malloc(sizeof(message));
        assert(curr_message != NULL);
        curr_message->filedes = filedes;
        curr_message->header_length = -1;
        curr_message->content_length = -1;
        curr_message->bytes_of_content_read = 0;
        curr_message->header = NULL;
        curr_message->content = NULL;
        curr_message->header_complete = false;
        curr_message->msg_complete = false;
        curr_message->content_type = -1;

        curr_message->chunk_state = CHUNK_SIZE;
        curr_message->chunk_size = 0;
        curr_message->bytes_read_in_chunk = 0;
        memset(curr_message->chunk_size_str, 0, sizeof(curr_message->chunk_size_str));
        curr_message->chunk_size_str_index = 0; 
        append(all_messages, curr_message);
    }

    if (!(curr_message->header_complete)) {
        char *header_end = strstr(buffer, "\r\n\r\n");
        if (header_end != NULL) {
            curr_message->header_complete = true;
            size_t header_length = header_end - buffer + 4;
            curr_message->header_length = header_length;
            curr_message->header = malloc(header_length + 1);
            assert(curr_message->header != NULL);
            memcpy(curr_message->header, buffer, header_length);
            curr_message->header[header_length] = '\0';
            buffer += header_length;
            n -= header_length;

            modify_accept_encoding(curr_message);
        }
    }
    if (curr_message->header_complete && !(curr_message->msg_complete)) {
        if (curr_message->content_length == -1) {
            char *content_length_ptr = get_content_length_ptr(curr_message->header);
            if (content_length_ptr != NULL) {
                curr_message->content_length = atoi(content_length_ptr + 16);
                curr_message->content_type = NORMAL_ENCODING;
            }
        }
        if (curr_message->content_length == -1) {
            char *transfer_encoding = strstr(curr_message->header, "Transfer-Encoding: ");
            if (transfer_encoding != NULL) {
                if (strstr(transfer_encoding, "chunked") != NULL) {
                    curr_message->content_length = 0;
                    curr_message->content_type = CHUNKED_ENCODING;
                } else if (strstr(transfer_encoding, "Chunked") != NULL) {
                    curr_message->content_length = 0;
                    curr_message->content_type = CHUNKED_ENCODING;
                } else if (strstr(transfer_encoding, "CHUNKED") != NULL) {
                    curr_message->content_length = 0;
                    curr_message->content_type = CHUNKED_ENCODING;
                }
            }
        }
        if (curr_message->content_length == -1 && curr_message->content_type != CHUNKED_ENCODING) {
            curr_message->content_length = 0;
            curr_message->msg_complete = true;
        }

        if (curr_message->content_length > 0 && n > 0 && curr_message->content_type == NORMAL_ENCODING) {
            if (curr_message->content == NULL) {
                curr_message->content = malloc(curr_message->content_length);
                assert(curr_message->content != NULL);
            }

            int remaining_length = curr_message->content_length - curr_message->bytes_of_content_read;
            int copy_length;
            if (n <= remaining_length) {
                copy_length = n;
            } else {
                copy_length = remaining_length;
                printf("ERROR: Content length exceeded\n");
            }
            memcpy(curr_message->content + curr_message->bytes_of_content_read, buffer, copy_length);
            curr_message->bytes_of_content_read += copy_length;

            if (curr_message->bytes_of_content_read >= curr_message->content_length) {
                curr_message->msg_complete = true;
            }
        }
        // else if (curr_message->content_type == CHUNKED_ENCODING && n > 0) {
        else if (curr_message->content_type == CHUNKED_ENCODING) {
            insert_buffer_into_message(curr_message, buffer, n);
        }
    }

    return curr_message;
}

void insert_buffer_into_message(message *msg, char *buffer, int buffer_length) {
    // Ensure header is complete before processing chunked content
    if (!msg->header_complete) {
        // Error handling or return if header is not complete
        return;
    }

    int i = 0; // Index into buffer

    while (i < buffer_length) {
        // Process chunked content
        switch (msg->chunk_state) {
            case CHUNK_SIZE:
                // Parse the chunk size
                while (i < buffer_length) {
                    char c = buffer[i++];
                    if (c == '\r') {
                        // End of chunk size line
                        msg->chunk_size_str[msg->chunk_size_str_index] = '\0';
                        msg->chunk_size = (int)strtol(msg->chunk_size_str, NULL, 16);
                        msg->chunk_size_str_index = 0;
                        msg->chunk_state = CHUNK_SIZE_LF;
                        break;
                    } else if (c == ';') {
                        // Ignore chunk extensions
                        while (i < buffer_length && buffer[i] != '\r') {
                            i++;
                        }
                    } else {
                        // Append to chunk_size_str
                        if (msg->chunk_size_str_index < (int)(sizeof(msg->chunk_size_str) - 1)) {
                            msg->chunk_size_str[msg->chunk_size_str_index++] = c;
                        } else {
                            // Error: chunk size string too long
                            return;
                        }
                    }
                }
                break;

            case CHUNK_SIZE_LF:
                if (i < buffer_length) {
                    char c = buffer[i++];
                    if (c == '\n') {
                        if (msg->chunk_size == 0) {
                            // Last chunk
                            msg->chunk_state = CHUNK_DONE;
                            msg->msg_complete = true;
                        } else {
                            msg->bytes_read_in_chunk = 0;
                            msg->chunk_state = CHUNK_DATA;
                        }
                    } else {
                        // Error: Expected '\n'
                        return;
                    }
                } else {
                    // Need more data
                    return;
                }
                break;

            case CHUNK_DATA:
                {
                    int bytes_to_read = msg->chunk_size - msg->bytes_read_in_chunk;
                    int bytes_available = buffer_length - i;
                    int bytes_to_copy = bytes_to_read < bytes_available ? bytes_to_read : bytes_available;

                    // Allocate or expand the content buffer
                    if (msg->content == NULL) {
                        msg->content_length = bytes_to_copy;
                        msg->content = malloc(msg->content_length);
                        if (msg->content == NULL) {
                            // Handle malloc failure
                            return;
                        }
                    } else {
                        msg->content_length += bytes_to_copy;
                        unsigned char *new_content = realloc(msg->content, msg->content_length);
                        if (new_content == NULL) {
                            // Handle realloc failure
                            return;
                        }
                        msg->content = new_content;
                    }

                    // Copy data to msg->content
                    memcpy(msg->content + msg->bytes_of_content_read, buffer + i, bytes_to_copy);
                    msg->bytes_read_in_chunk += bytes_to_copy;
                    msg->bytes_of_content_read += bytes_to_copy;
                    i += bytes_to_copy;

                    if (msg->bytes_read_in_chunk == msg->chunk_size) {
                        msg->chunk_state = CHUNK_DATA_CR;
                    }
                }
                break;

            case CHUNK_DATA_CR:
                if (i < buffer_length) {
                    char c = buffer[i++];
                    if (c == '\r') {
                        msg->chunk_state = CHUNK_DATA_LF;
                    } else {
                        // Error: Expected '\r'
                        return;
                    }
                } else {
                    // Need more data
                    return;
                }
                break;

            case CHUNK_DATA_LF:
                if (i < buffer_length) {
                    char c = buffer[i++];
                    if (c == '\n') {
                        msg->chunk_state = CHUNK_SIZE;
                    } else {
                        // Error: Expected '\n'
                        return;
                    }
                } else {
                    // Need more data
                    return;
                }
                break;

            case CHUNK_DONE:
                // All chunks received; optionally process trailers here
                i = buffer_length; // Consume remaining data
                msg->msg_complete = true;
                break;

            default:
                // Error: Invalid state
                return;
        }
    }
}

#include <ctype.h>

void modify_accept_encoding(message *curr_message) {
    char *header = curr_message->header;
    size_t header_length = curr_message->header_length;
    size_t i = 0;

    // The new Accept-Encoding line
    const char *new_line = "Accept-Encoding: identity\r\n";
    size_t new_line_length = strlen(new_line);

    while (i < header_length) {
        // Find the end of the current line
        size_t line_start = i;
        while (i < header_length - 1 && !(header[i] == '\r' && header[i + 1] == '\n')) {
            i++;
        }

        if (i >= header_length - 1) {
            // End of header reached or malformed header
            break;
        }

        // Now, header[line_start .. i-1] is the current line (excluding "\r\n")
        size_t line_length = i - line_start;

        // Check if the line contains ':'
        char *colon = memchr(&header[line_start], ':', line_length);
        if (colon) {
            size_t field_name_length = colon - &header[line_start];

            // Remove any trailing whitespace from field name
            while (field_name_length > 0 &&
                   isspace((unsigned char)header[line_start + field_name_length - 1])) {
                field_name_length--;
            }

            // Compare field name to "Accept-Encoding" case-insensitively
            if (field_name_length == strlen("Accept-Encoding") &&
                strncasecmp(&header[line_start], "Accept-Encoding", field_name_length) == 0) {
                // Found the Accept-Encoding header
                size_t old_line_length = (i + 2) - line_start; // Including "\r\n"

                ssize_t diff = (ssize_t)new_line_length - (ssize_t)old_line_length;

                if (diff != 0) {
                    // Shift data to accommodate new line length
                    memmove(&header[line_start + new_line_length],
                            &header[line_start + old_line_length],
                            header_length - (line_start + old_line_length));
                }

                // Copy new line into header
                memcpy(&header[line_start], new_line, new_line_length);

                // Update header length and null-terminate
                curr_message->header_length += diff;
                header_length += diff;
                header[curr_message->header_length] = '\0';

                // Header updated; exit the loop
                break;
            }
        }

        // Move past the "\r\n"
        i += 2;
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

void inject_script_into_html(message *msg) {
    const char *body_tag = "</body>";
    char *pos = strstr((const char *)msg->content, body_tag);

    if (pos) {
        const char *script_to_inject = 
            "<script>"
            "document.addEventListener('DOMContentLoaded', () => {"
            "  const factCheckButton = document.createElement('button');"
            "  factCheckButton.innerText = 'Fact Check Selected';"
            "  factCheckButton.style.position = 'fixed';"
            "  factCheckButton.style.bottom = '10px';"
            "  factCheckButton.style.right = '10px';"
            "  factCheckButton.style.zIndex = '9999';"
            "  factCheckButton.style.padding = '10px';"
            "  factCheckButton.style.backgroundColor = 'blue';"
            "  factCheckButton.style.borderRadius = '5px';"
            "  factCheckButton.style.cursor = 'pointer';"
            "  factCheckButton.style.color = 'white';"
            "  factCheckButton.style.border = 'none';"
            "  document.body.appendChild(factCheckButton);"
            "  factCheckButton.addEventListener('click', async () => {"
            "    const selection = window.getSelection().toString();"
            "    if (selection) {"
            "      const response = await fetch('/fact-check', {"
            "        method: 'POST',"
            "        headers: { 'Content-Type': 'application/json' },"
            "        body: JSON.stringify({ text: selection })"
            "      });"
            "      const result = await response.json();"
            "      alert(`Fact Check Result: ${result.factCheck}`);"
            "    }"
            "  });"
            "});"
            "</script>";

        size_t script_length = strlen(script_to_inject);
        size_t new_content_length = msg->content_length + script_length;

        // Allocate new memory for the modified content
        char *new_content = malloc(new_content_length + 1);
        if (!new_content) {
            perror("malloc failed");
            return;
        }

        // Copy the content up to the </body> tag
        size_t prefix_length = pos - (char *)msg->content;
        strncpy(new_content, (char *)msg->content, prefix_length);

        // Inject the script
        strcpy(new_content + prefix_length, script_to_inject);

        // Append the </body> tag and the rest of the response
        strcpy(new_content + prefix_length + script_length, pos);

        // Update the message content
        free(msg->content);
        msg->content = (unsigned char *)new_content;
        msg->content_length = new_content_length;

        // Replace the Content-Length in the header
        char *content_length_ptr = get_content_length_ptr(msg->header);
        if (content_length_ptr) {
            // Remove the old Content-Length header
            char *content_length_end = strstr(content_length_ptr, "\r\n");
            size_t header_suffix_length = strlen(content_length_end + 2); // +2 to skip \r\n
            memmove(content_length_ptr, content_length_end + 2, header_suffix_length + 1); // +1 to include the null terminator

            // Insert the new Content-Length header
            char new_content_length_header[50];
            snprintf(new_content_length_header, sizeof(new_content_length_header), "Content-Length: %zu\r\n", new_content_length);
            size_t new_header_length = strlen(new_content_length_header);
            memmove(content_length_ptr + new_header_length, content_length_ptr, header_suffix_length + 1); // +1 to include the null terminator
            memcpy(content_length_ptr, new_content_length_header, new_header_length);
        }
    }
}



char *get_content_length_ptr(char *str) {
    assert(str != NULL);
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

void print_buffer(unsigned char *m, unsigned size)
{
    // printf("Type: %d, Source: %s, Dest: %s, Length: %d, ID: %d\n",
    //        m->h.type, m->h.source, m->h.dest, m->h.length, m->h.message_id);
    // printf("\nSize of buffer: %d\n", size);
    if (size > 0) {
        printf("Message content is: ");
        for (unsigned offset = 0; offset < size; offset++) {
            if (m[offset] == '\0') {
                putchar('.');
            }

            else {
                putchar(m[offset]);
            }
        }

        printf("\n");
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

// char *reverse_strstr(char *haystack, const char *needle) {
//     if (!*needle) {
//         return (char *)haystack;
//     }

//     char *result = NULL;
//     char *current;

//     while ((current = strstr(haystack, needle)) != NULL) {
//         result = current;
//         haystack = current + 1;
//     }

//     return result;
// }
