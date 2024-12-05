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
#include <ctype.h>
#include <zlib.h>

#define DECOMPRESSED_BUFFER_SIZE 8192
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
        printf("SSL connection failed to server\n");
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
            printf("\nSSL handshake with client FAILED\n");
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
        // NOT a CONNECT request
        return false;
    }
}

bool read_client_request(int client_fd, Node **ssl_contexts, 
    fd_set *active_read_fd_set, int *max_fd, Cache_T *cache, Node **all_messages, int LLM_sockfd, struct sockaddr_un python_addr) {
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
        char buffer_arr[BUFFER_SIZE];
        char *buffer = buffer_arr;
        int read_n, write_n;

        read_n = SSL_read(curr_context->client_ssl, buffer, BUFFER_SIZE);
        
        if (read_n > 0) {
            incomplete_message *curr_message = get_incomplete_message_by_filedes(*all_messages, curr_context->client_fd);
            curr_message = modify_header_data(&curr_message, buffer, curr_context->client_fd, all_messages);

            // Seeing whether the message needs to be fact-checked
            char *fact_check = strstr(curr_message->header, "fact-check-CS112-Final");
            if (fact_check != NULL) {
                // The client has asked for data to be fact-checked
                char *content_without_header = buffer + curr_message->original_header_length;
                char *end_of_message = strstr(content_without_header, "\"}");
                if (end_of_message != NULL) {
                    end_of_message[2] = '\0';
                }

                if (content_without_header[0] != '{' || content_without_header[strlen(content_without_header) - 1] != '}') {
                    printf("Content is not a JSON object\n");
                    return true;
                }

                printf("Content to Fact Check: %s\n", content_without_header);

                if (sendto(LLM_sockfd, content_without_header, strlen(content_without_header), 0, (struct sockaddr *)&python_addr, sizeof(python_addr)) == -1) {
                    printf("\nFAILED TO SEND TO PYTHON SCRIPT\n");
                    close(LLM_sockfd);
                    return false;
                }
                printf("Waiting for a response from Python script\n");

                socklen_t addr_len = sizeof(python_addr);
                char LLM_buffer[BUFFER_SIZE];
                int num_bytes_from_LLM = recvfrom(LLM_sockfd, LLM_buffer, sizeof(LLM_buffer), 0, (struct sockaddr *)&python_addr, &addr_len);
                // printf("Received %d bytes from Python script\n", num_bytes_from_LLM);
                if (num_bytes_from_LLM == -1) {
                    perror("Receive failed");
                    close(LLM_sockfd);
                    return 1;
                }

                char *fact_check_response = "HTTP/1.1 200 OK\r\n"
                                            "Content-Type: application/json; charset=utf-8\r\n"
                                            "Content-Length: %d\r\n"
                                            "\r\n"
                                            "%s";

                char fact_check_response_buffer[20000];
                // int static_part_length = strlen("{\"factCheck\": }"); // Length of the fixed JSON structure
                // int content_length = static_part_length + num_bytes_from_LLM;
                // snprintf(fact_check_response_buffer, sizeof(fact_check_response_buffer), fact_check_response, content_length, LLM_buffer);
                snprintf(fact_check_response_buffer, sizeof(fact_check_response_buffer), fact_check_response, num_bytes_from_LLM, LLM_buffer);

                // printf("Fact Check Response:\n%s\n", fact_check_response_buffer);
                write_n = SSL_write(curr_context->client_ssl, fact_check_response_buffer, strlen(fact_check_response_buffer));
                printf("Wrote fact check response to client\n");
                if (write_n <= 0) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                    return false;
                }
            }

            else {
                // Regular request coming from client
                curr_message->content_length_read += read_n;
                if (!(curr_message->header_sent) && curr_message->header_complete) {
                    int header_length = strlen(curr_message->header);
                    write_n = SSL_write(curr_context->server_ssl, curr_message->header, header_length);

                    if (write_n <= 0) {
                        free(curr_message->header);
                        removeNode(all_messages, curr_message);
                        return false;
                    }

                    // printf("Wrote header to server: %s\n", curr_message->header);

                    curr_message->header_sent = true;
                    curr_message->content_length_read -= curr_message->original_header_length;
                    buffer += curr_message->original_header_length;
                    read_n -= curr_message->original_header_length;
                }

                if (read_n > 0) {
                    if (curr_message->original_content_type != NORMAL_ENCODING) {
                        write_n = SSL_write(curr_context->server_ssl, buffer, read_n);
                        if (write_n <= 0) {
                            free(curr_message->header);
                            removeNode(all_messages, curr_message);
                            return false;
                        }

                        if (contains_chunk_end(buffer, read_n)) {
                            free(curr_message->header);
                            removeNode(all_messages, curr_message);
                        }
                    }
                    else {
                        int chunk_data_length = 0;
                        char *chunked_data = convert_to_chunked_encoding(buffer, read_n, curr_message, &chunk_data_length);
                        if (chunked_data == NULL) {
                            return false;
                        }
                        write_n = SSL_write(curr_context->server_ssl, chunked_data, chunk_data_length);
                        if (write_n <= 0) {
                            free(curr_message->header);
                            removeNode(all_messages, curr_message);
                            return false;
                        }

                        if (curr_message->content_length_read >= curr_message->content_length) {
                            removeNode(all_messages, curr_message);
                        }
                    }
                }
            }

            return true;
        } else {
            int ssl_error = SSL_get_error(curr_context->client_ssl, read_n);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                return true; // Keep the connection open
            } else {
                return false; // Close the connection
            }
        }
    }
}

char *convert_to_chunked_encoding(char *buffer, int buffer_length, incomplete_message *msg, int *chunked_data_length) {
    if (buffer == NULL || buffer_length <= 0 || msg == NULL) {
        return NULL;
    }

    // Calculate the maximum size of the output, considering chunk size metadata
    // Each chunk has: <chunk size in hex>\r\n<data>\r\n
    // Plus space for the final "0\r\n\r\n" and null terminator if necessary
    int max_output_size = buffer_length + (buffer_length / 16 + 1) * 10 + 10;
    char *chunked = malloc(max_output_size);
    if (!chunked) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    char *output_ptr = chunked; // Pointer for writing into the output buffer
    int remaining = buffer_length; // Remaining bytes in the input buffer
    char *input_ptr = buffer; // Pointer for reading from the input buffer

    while (remaining > 0) {
        // Calculate the size of the current chunk
        int chunk_size = remaining;

        // Write the chunk size in hexadecimal, followed by \r\n
        int header_length = sprintf(output_ptr, "%x\r\n", chunk_size);
        output_ptr += header_length;

        // Copy the chunk data into the output buffer
        memcpy(output_ptr, input_ptr, chunk_size);
        output_ptr += chunk_size;

        // Add \r\n after the chunk data
        memcpy(output_ptr, "\r\n", 2);
        output_ptr += 2;

        // Update the pointers and decrement the remaining data
        input_ptr += chunk_size;
        remaining -= chunk_size;
    }

    // If all content has been read, append the final chunk terminator
    if (msg->content_length_read >= msg->content_length) {
        memcpy(output_ptr, "0\r\n\r\n", 5);
        output_ptr += 5;
    }

    // Calculate the length of the chunked data
    *chunked_data_length = output_ptr - chunked;

    // Null-terminate the output buffer
    *output_ptr = '\0';

    return chunked;
}

bool read_server_response(int server_fd, Node **ssl_contexts, Node **all_messages) {
    Context_T *curr_context = get_ssl_context_by_server_fd(*ssl_contexts, server_fd);
    if (curr_context == NULL) {
        return false;
    }

    char buffer_arr[BUFFER_SIZE];
    char *buffer = buffer_arr;
    int read_n = SSL_read(curr_context->server_ssl, buffer, BUFFER_SIZE);

    int write_n;

    if (read_n > 0) {
        incomplete_message *curr_message = get_incomplete_message_by_filedes(*all_messages, curr_context->server_fd);
        curr_message = modify_header_data(&curr_message, buffer, curr_context->server_fd, all_messages);            

        curr_message->content_length_read += read_n;
        if (!(curr_message->header_sent) && curr_message->header_complete) {
            int header_length = strlen(curr_message->header);
            write_n = SSL_write(curr_context->client_ssl, curr_message->header, header_length);

            if (write_n <= 0) {
                free(curr_message->header);
                removeNode(all_messages, curr_message);
                return false;
            }

            // printf("Wrote header to client: %s\n", curr_message->header);

            curr_message->header_sent = true;
            curr_message->content_length_read -= curr_message->original_header_length;
            buffer += curr_message->original_header_length;
            read_n -= curr_message->original_header_length;
        }

        if (read_n > 0) {

            if (curr_message->original_content_type != NORMAL_ENCODING) {
                // printf("original_content_type: %d\n", curr_message->original_content_type);
                
                // Injection
                int to_send_length = read_n;
                char *to_send = inject_script_into_chunked_html(buffer, &to_send_length);
                write_n = SSL_write(curr_context->client_ssl, to_send, to_send_length);

                // No injection
                // write_n = SSL_write(curr_context->client_ssl, buffer, read_n);

                if (write_n <= 0) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                    return false;
                }

                // printf("Wrote chunked data to client (NOT NORMAL ENCODING)\n");
                // for (int i = 0; i < to_send_length; i++) {
                //     if (isalnum(to_send[i])) {
                //         putchar(to_send[i]);
                //     }
                // }
                // printf("\n");

                if (contains_chunk_end(buffer, read_n)) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                }
            }

            else {
                int chunk_data_length = 0;
                char *chunked_data = convert_to_chunked_encoding(buffer, read_n, curr_message, &chunk_data_length);

                if (chunked_data == NULL) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                    return false;
                }

                // Injection
                int to_send_length = chunk_data_length;
                char *to_send = inject_script_into_chunked_html(chunked_data, &to_send_length);
                write_n = SSL_write(curr_context->client_ssl, to_send, to_send_length);
                
                // No injection
                // write_n = SSL_write(curr_context->client_ssl, chunked_data, chunk_data_length);
                
                if (write_n <= 0) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                    return false;
                }

                // printf("Wrote chunked data to client (NORMAL ENCODING)\n");
                // for (int i = 0; i < to_send_length; i++) {
                //     if (isalnum(to_send[i])) {
                //         putchar(to_send[i]);
                //     }
                // }
                // printf("\n");

                if (curr_message->content_length_read >= curr_message->content_length) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                }
            }
        }

        return true;
    }  
    
    else {
        int ssl_error = SSL_get_error(curr_context->server_ssl, read_n);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            // Need to retry the operation later
            return true; // Keep the connection open
        } else {
            return false; // Close the connection
        }
    }
}

bool contains_chunk_end(char *buffer, int buffer_length) {
    for (int i = 0; i < buffer_length - 4; i++) {
        if (buffer[i] == '0' && buffer[i + 1] == '\r' && buffer[i + 2] == '\n' && buffer[i + 3] == '\r' && buffer[i + 4] == '\n') {
            return true;
        }
    }
    return false;
}

// void update_message_header_no_chunk(message *msg) {
//     if (msg == NULL || msg->header == NULL) {
//         fprintf(stderr, "Error: message or header is NULL.\n");
//         return;
//     }

//     const char *chunked_encoding = "Transfer-Encoding: chunked\r\n";
//     char content_length_header[64];

//     // Check if "Transfer-Encoding: chunked" exists in the header
//     char *chunked_position = strstr(msg->header, chunked_encoding);
//     if (chunked_position == NULL) {
//         fprintf(stderr, "Error: 'Transfer-Encoding: chunked' not found in header.\n");
//         return;
//     }

//     // Create the new "Content-Length" header string
//     snprintf(content_length_header, sizeof(content_length_header), "Content-Length: %d\r\n", msg->content_length);

//     // Calculate new header size
//     size_t header_prefix_length = chunked_position - msg->header; // Length of header before "Transfer-Encoding: chunked"
//     size_t header_suffix_length = strlen(chunked_position + strlen(chunked_encoding)); // Length of header after "Transfer-Encoding: chunked"
//     size_t new_header_length = header_prefix_length + strlen(content_length_header) + header_suffix_length;

//     // Allocate memory for the new header
//     char *new_header = (char *)malloc(new_header_length + 1);
//     if (new_header == NULL) {
//         fprintf(stderr, "Error: Memory allocation failed for new header.\n");
//         return;
//     }

//     // Build the new header
//     strncpy(new_header, msg->header, header_prefix_length); // Copy part before "Transfer-Encoding: chunked"
//     new_header[header_prefix_length] = '\0'; // Null-terminate temporarily
//     strcat(new_header, content_length_header); // Append "Content-Length: ..."
//     strcat(new_header, chunked_position + strlen(chunked_encoding)); // Append part after "Transfer-Encoding: chunked"

//     // Free the old header and assign the new header to msg
//     free(msg->header);
//     msg->header = new_header;
//     msg->header_length = (int)new_header_length;
// }

incomplete_message *modify_header_data(incomplete_message **msg, char *buffer, int filedes, Node **all_messages) {
    incomplete_message *curr_message = *msg;
    if (curr_message == NULL) {
        curr_message = malloc(sizeof(incomplete_message));
        assert(curr_message != NULL);
        curr_message->filedes = filedes;
        curr_message->content_length = -1;
        curr_message->content_length_read = 0;
        curr_message->header_complete = false;
        curr_message->header = NULL;
        curr_message->original_header_length = 0;
        curr_message->header_sent = false;
        curr_message->original_content_type = OTHER_ENCODING;
        append(all_messages, curr_message);
    }

    if (!(curr_message->header_complete)) {
        char *header_end = strstr(buffer, "\r\n\r\n");
        if (header_end != NULL) {
            curr_message->header_complete = true;
            size_t header_length = header_end - buffer + 4;
            curr_message->original_header_length = (int)header_length;
            curr_message->header = malloc(header_length + 1);
            assert(curr_message->header != NULL);
            memcpy(curr_message->header, buffer, header_length);
            curr_message->header[header_length] = '\0';
            buffer += header_length;

            modify_content_type(curr_message);
            modify_accept_encoding(curr_message);
        }
    }

    return curr_message;
}

void modify_content_type(incomplete_message *msg) {
    if (msg == NULL || msg->header == NULL) {
        return;
    }

    const char *content_length_str = "Content-Length:";
    const char *transfer_encoding_str = "Transfer-Encoding: chunked";

    char *header = msg->header;
    char *content_length_start = strcasestr(header, content_length_str); // Case-insensitive search for Content-Length

    if (content_length_start) {
        msg->original_content_type = NORMAL_ENCODING;

        // Extract the content length value
        char *content_length_value = content_length_start + strlen(content_length_str);
        while (*content_length_value == ' ') {
            content_length_value++;
        }
        msg->content_length = atoi(content_length_value);

        // Find the end of the Content-Length line
        char *line_end = strstr(content_length_start, "\r\n");
        if (line_end) {
            // Remove the Content-Length line
            // size_t line_length = line_end + 2 - content_length_start;
            memmove(content_length_start, line_end + 2, strlen(line_end + 2) + 1);
        } else {
            // Handle case where Content-Length is the last line
            *content_length_start = '\0';
        }
    }

    // Check if Transfer-Encoding: chunked already exists
    char *transfer_encoding_start = strcasestr(header, transfer_encoding_str);
    if (transfer_encoding_start) {
        msg->original_content_type = CHUNKED_ENCODING;
    }

    if (msg->original_content_type == NORMAL_ENCODING) {
        // If Transfer-Encoding: chunked is not present, add it
        const char *chunked_line = "\r\nTransfer-Encoding: chunked";
        size_t chunked_line_length = strlen(chunked_line);

        // Find the end of the header
        char *header_end = strstr(header, "\r\n\r\n");
        if (header_end) {
            size_t header_prefix_length = header_end - header;
            size_t new_header_length = header_prefix_length + chunked_line_length + 4; // +4 for \r\n\r\n

            // Allocate memory for the new header
            char *new_header = malloc(new_header_length + 1);
            if (!new_header) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }

            // Build the new header
            strncpy(new_header, header, header_prefix_length); // Copy part before \r\n\r\n
            new_header[header_prefix_length] = '\0'; // Null-terminate temporarily
            strcat(new_header, chunked_line); // Append Transfer-Encoding: chunked
            strcat(new_header, "\r\n\r\n"); // Append \r\n\r\n

            // Replace old header with new header
            free(msg->header);
            msg->header = new_header;
        }
    }
}


// void insert_buffer_into_message(message *msg, char *buffer, int buffer_length) {
//     // Ensure header is complete before processing chunked content
//     if (!msg->header_complete) {
//         // Error handling or return if header is not complete
//         return;
//     }

//     int i = 0; // Index into buffer

//     while (i < buffer_length) {
//         // Process chunked content
//         switch (msg->chunk_state) {
//             case CHUNK_SIZE:
//                 // Parse the chunk size
//                 while (i < buffer_length) {
//                     char c = buffer[i++];
//                     if (c == '\r') {
//                         // End of chunk size line
//                         msg->chunk_size_str[msg->chunk_size_str_index] = '\0';
//                         msg->chunk_size = (int)strtol(msg->chunk_size_str, NULL, 16);
//                         msg->chunk_size_str_index = 0;
//                         msg->chunk_state = CHUNK_SIZE_LF;
//                         break;
//                     } else if (c == ';') {
//                         // Ignore chunk extensions
//                         while (i < buffer_length && buffer[i] != '\r') {
//                             i++;
//                         }
//                     } else {
//                         // Append to chunk_size_str
//                         if (msg->chunk_size_str_index < (int)(sizeof(msg->chunk_size_str) - 1)) {
//                             msg->chunk_size_str[msg->chunk_size_str_index++] = c;
//                         } else {
//                             // Error: chunk size string too long
//                             return;
//                         }
//                     }
//                 }
//                 break;

//             case CHUNK_SIZE_LF:
//                 if (i < buffer_length) {
//                     char c = buffer[i++];
//                     if (c == '\n') {
//                         if (msg->chunk_size == 0) {
//                             // Last chunk
//                             msg->chunk_state = CHUNK_DONE;
//                             msg->msg_complete = true;
//                         } else {
//                             msg->bytes_read_in_chunk = 0;
//                             msg->chunk_state = CHUNK_DATA;
//                         }
//                     } else {
//                         // Error: Expected '\n'
//                         return;
//                     }
//                 } else {
//                     // Need more data
//                     return;
//                 }
//                 break;

//             case CHUNK_DATA:
//                 {
//                     int bytes_to_read = msg->chunk_size - msg->bytes_read_in_chunk;
//                     int bytes_available = buffer_length - i;
//                     int bytes_to_copy = bytes_to_read < bytes_available ? bytes_to_read : bytes_available;

//                     // Allocate or expand the content buffer
//                     if (msg->content == NULL) {
//                         msg->content_length = bytes_to_copy;
//                         msg->content = malloc(msg->content_length);
//                         if (msg->content == NULL) {
//                             // Handle malloc failure
//                             return;
//                         }
//                     } else {
//                         msg->content_length += bytes_to_copy;
//                         unsigned char *new_content = realloc(msg->content, msg->content_length);
//                         if (new_content == NULL) {
//                             // Handle realloc failure
//                             return;
//                         }
//                         msg->content = new_content;
//                     }

//                     // Copy data to msg->content
//                     memcpy(msg->content + msg->bytes_of_content_read, buffer + i, bytes_to_copy);
//                     msg->bytes_read_in_chunk += bytes_to_copy;
//                     msg->bytes_of_content_read += bytes_to_copy;
//                     i += bytes_to_copy;

//                     if (msg->bytes_read_in_chunk == msg->chunk_size) {
//                         msg->chunk_state = CHUNK_DATA_CR;
//                     }
//                 }
//                 break;

//             case CHUNK_DATA_CR:
//                 if (i < buffer_length) {
//                     char c = buffer[i++];
//                     if (c == '\r') {
//                         msg->chunk_state = CHUNK_DATA_LF;
//                     } else {
//                         // Error: Expected '\r'
//                         return;
//                     }
//                 } else {
//                     // Need more data
//                     return;
//                 }
//                 break;

//             case CHUNK_DATA_LF:
//                 if (i < buffer_length) {
//                     char c = buffer[i++];
//                     if (c == '\n') {
//                         msg->chunk_state = CHUNK_SIZE;
//                     } else {
//                         // Error: Expected '\n'
//                         return;
//                     }
//                 } else {
//                     // Need more data
//                     return;
//                 }
//                 break;

//             case CHUNK_DONE:
//                 // All chunks received; optionally process trailers here
//                 i = buffer_length; // Consume remaining data
//                 msg->msg_complete = true;
//                 break;

//             default:
//                 // Error: Invalid state
//                 return;
//         }
//     }
// }

void modify_accept_encoding(incomplete_message *curr_message) {
    char *header = curr_message->header;
    size_t header_length = strlen(header);
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
                header_length += diff;
                header[header_length] = '\0';

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

char *inject_script_into_chunked_html(char *buffer, int *buffer_length) {
    // char *quora_last_line = "addEventListener(\"load\",function(){setTimeout(function(){window.navigator.serviceWorker.register(\"/sw.js\").then(function(t){t.update().catch(function(){})})},100)})";
    const char *body_tag = "</body>";

    // if (strstr(buffer, quora_last_line) == NULL || strstr(buffer, body_tag) == NULL) {
    //     return buffer;
    // }

    // printf("Attempting to inject script into chunked HTML\n");

    // List of common page-specific indicators or end-of-body markers
    const char *page_indicators[] = {
        // Quora-specific script
        "addEventListener(\"load\",function(){setTimeout(function(){window.navigator.serviceWorker.register(\"/sw.js\").then(function(t){t.update().catch(function(){})},100)}))",
        // Generic end-of-body indicators
        "</body>",
        "<!-- End of body -->",
        "<!-- Page content end -->",
        "</html>"
    };
    
    // Number of indicators to check
    int num_indicators = sizeof(page_indicators) / sizeof(page_indicators[0]);
    
    // Flag to check if any indicator is found
    int indicator_found = 0;
    
    // Check for any of the indicators
    for (int i = 0; i < num_indicators; i++) {
        if (strstr(buffer, page_indicators[i]) != NULL) {
            indicator_found = 1;
            break;
        }
    }
    
    // If no indicator found, return the original buffer
    if (!indicator_found) {
        return buffer;
    }
    
    printf("Attempting to inject script into chunked HTML\n");


    const char *script_to_inject = 
            "<script>"
            "document.addEventListener('DOMContentLoaded', () => {"
            "  const factCheckButton = document.createElement('button');"
            "  factCheckButton.innerText = 'Run Fact Check';"
            "  factCheckButton.style.position = 'fixed';"
            "  factCheckButton.style.bottom = '10px';"
            "  factCheckButton.style.right = '10px';"
            "  factCheckButton.style.zIndex = '9999';"
            "  factCheckButton.style.padding = '15px';"
            "  factCheckButton.style.backgroundColor = 'white';"
            "  factCheckButton.style.borderRadius = '5px';"
            "  factCheckButton.style.cursor = 'pointer';"
            "  factCheckButton.style.color = 'black';"
            "  factCheckButton.style.border = 'none';"
            "  factCheckButton.style.fontSize = 'large';"
            "  factCheckButton.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';"
            "  factCheckButton.style.transition = 'background-color 0.3s';"
            "  factCheckButton.addEventListener('mouseover', () => {"
            "     factCheckButton.style.backgroundColor = 'gainsboro';"
            "  });"
            "  factCheckButton.addEventListener('mouseout', () => {"
            "     factCheckButton.style.backgroundColor = 'white';"
            "  });"
            "  document.body.appendChild(factCheckButton);"
            ""
            "  const toggleButton = document.createElement('button');"
            "  toggleButton.innerText = '↑';"
            "  toggleButton.style.position = 'fixed';"
            "  toggleButton.style.bottom = '75px';"
            "  toggleButton.style.right = '10px';"
            "  toggleButton.style.zIndex = '9999';"
            "  toggleButton.style.padding = '10px';"
            "  toggleButton.style.backgroundColor = 'white';"
            "  toggleButton.style.borderRadius = '5px';"
            "  toggleButton.style.cursor = 'pointer';"
            "  toggleButton.style.color = 'black';"
            "  toggleButton.style.border = 'none';"
            "  toggleButton.style.fontSize = 'large';"
            "  toggleButton.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';"
            "  toggleButton.style.transition = 'background-color 0.3s';"
            "  toggleButton.addEventListener('mouseover', () => {"
            "     toggleButton.style.backgroundColor = 'gainsboro';"
            "  });"
            "  toggleButton.addEventListener('mouseout', () => {"
            "     toggleButton.style.backgroundColor = 'white';"
            "  });"
            "  document.body.appendChild(toggleButton);"
            ""
            "  let popupDiv = null;" // Store reference to the popupDiv
            "  let is_first = true;"
            ""
            "  factCheckButton.addEventListener('click', async () => {"
            "    const selection = window.getSelection().toString();"
            "    if (selection) {"
            "      if (!popupDiv) {"
            "        popupDiv = document.createElement('div');"
            "        popupDiv.style.position = 'fixed';"
            "        popupDiv.style.top = '10%';"
            "        popupDiv.style.left = '50%';"
            "        popupDiv.style.transform = 'translateX(-50%)';"
            "        popupDiv.style.maxHeight = '50%';"
            "        popupDiv.style.overflowY = 'auto';"
            "        popupDiv.style.padding = '20px';"
            "        popupDiv.style.width = '60%';"
            "        popupDiv.style.backgroundColor = 'white';"
            "        popupDiv.style.color = 'black';"
            "        popupDiv.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';"
            "        popupDiv.style.zIndex = '10000';"
            "        popupDiv.style.borderRadius = '8px';"
            "        popupDiv.style.display = 'none';" // Initially hidden
            "        popupDiv.innerHTML = "
            "          `<div style='display: flex; justify-content: space-between; align-items: center;'>"
            "            <button id='close-button' style='background: none; border: none; font-size: 18px; cursor: pointer; color: black'>&times;</button>"
            "          </div>"
            "          <div id='fact-check-results'></div>`;" // Container for cumulative results
            ""
            "        const closeButton = popupDiv.querySelector('#close-button');"
            "        closeButton.addEventListener('click', () => {"
            "          popupDiv.style.display = 'none';" // Hide the popupDiv
            "        });"
            ""
            "        document.body.appendChild(popupDiv);"
            "      }"
            ""
            "      popupDiv.style.display = 'block';" // Show the popupDiv
            "      const resultsContainer = popupDiv.querySelector('#fact-check-results');"
            ""
            "      const loadingMessage = document.createElement('p');"
            "      loadingMessage.style.fontSize = 'large';"
            "      loadingMessage.innerHTML = '<strong>Fact checking...<br><br></strong>';"
            "      resultsContainer.prepend(loadingMessage);"
            ""
            "      try {"
            "        const response = await fetch('https://www.quora.com/ajax/receive_POST?fact-check-CS112-Final=True', {"
            "          method: 'POST',"
            "          headers: { 'Content-Type': 'application/json' },"
            "          body: JSON.stringify({ text: selection })"
            "        });"
            "        const result = await response.json();"
            "        const factCheckResult = document.createElement('div');"
            "        if (is_first) {factCheckResult.innerHTML = `<p>${result.factCheck}</p>`; is_first = false}"
            "        else {factCheckResult.innerHTML = `<p>${result.factCheck}</p><hr style=\"margin: 30px auto; text-align: center; border: 1px black solid; width: 80%\">`;}"
            "        resultsContainer.prepend(factCheckResult);"
            "        loadingMessage.remove();"
            "      } catch (error) {"
            "        loadingMessage.remove();"
            "        alert('Unable to fact check. Please try again.');"
            "      }"
            "    }"
            "  });"
            ""
            "  toggleButton.addEventListener('click', () => {"
            "    if (popupDiv) {"
            "      popupDiv.style.display = popupDiv.style.display === 'none' ? 'block' : 'none';"
            "    }"
            "  });"
            "});"
            "</script>";





// const char *script_to_inject = 
//             "<script>"
//             "document.addEventListener('DOMContentLoaded', () => {"
//             "  const factCheckButton = document.createElement('button');"
//             "  factCheckButton.innerText = 'Fact Check Selected';"
//             "  factCheckButton.style.position = 'fixed';"
//             "  factCheckButton.style.bottom = '10px';"
//             "  factCheckButton.style.right = '10px';"
//             "  factCheckButton.style.zIndex = '9999';"
//             "  factCheckButton.style.padding = '15px';"
//             "  factCheckButton.style.backgroundColor = 'white';"
//             "  factCheckButton.style.borderRadius = '5px';"
//             "  factCheckButton.style.cursor = 'pointer';"
//             "  factCheckButton.style.color = 'black';"
//             "  factCheckButton.style.border = 'none';"
//             "  factCheckButton.style.fontSize = 'large';"
//             "  factCheckButton.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';"
//             "  factCheckButton.style.transition = 'background-color 0.3s';"
//             "  factCheckButton.addEventListener('mouseover', () => {"
//             "     factCheckButton.style.backgroundColor = 'gainsboro';"
//             "  });"
//             "  factCheckButton.addEventListener('mouseout', () => {"
//             "     factCheckButton.style.backgroundColor = 'white';"
//             "  });"
//             "  document.body.appendChild(factCheckButton);"
//             ""
//             "  factCheckButton.addEventListener('click', async () => {"
//             "    const selection = window.getSelection().toString();"
//             "    if (selection) {"
//             "      const popupDiv = document.createElement('div');"
//             "      popupDiv.style.position = 'fixed';"
//             "      popupDiv.style.top = '50%';"
//             "      popupDiv.style.left = '50%';"
//             "      popupDiv.style.transform = 'translate(-50%, -50%)';"
//             "      popupDiv.style.padding = '20px';"
//             "      popupDiv.style.width = '60%';"
//             "      popupDiv.style.backgroundColor = 'white';"
//             "      popupDiv.style.color = 'black';"
//             "      popupDiv.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';"
//             "      popupDiv.style.zIndex = '10000';"
//             "      popupDiv.style.borderRadius = '8px';"
//             "      popupDiv.innerHTML = "
//             "        `<div style='display: flex; justify-content: space-between; align-items: center;'>"
//             "          <button style='background: none; border: none; font-size: 18px; cursor: pointer; color: black'>&times;</button>"
//             "        </div>"
//             "        <p style='font-size: large'><strong>Fact checking...</strong></p>`;"
//             ""
//             "      const closeButton = popupDiv.querySelector('button');"
//             "      closeButton.addEventListener('click', () => {"
//             "        document.body.removeChild(popupDiv);"
//             "      });"
//             ""
//             "      document.body.appendChild(popupDiv);"
//             ""
//             "      try {"
//             "        const response = await fetch('https://www.quora.com/ajax/receive_POST?fact-check-CS112-Final=True', {"
//             "          method: 'POST',"
//             "          headers: { 'Content-Type': 'application/json' },"
//             "          body: JSON.stringify({ text: selection })"
//             "        });"
//             "        const result = await response.json();"
//             "        popupDiv.querySelector('p').innerHTML = result.factCheck;"
//             "      } catch (error) {"
//             "        popupDiv.querySelector('p').innerHTML = 'An error occurred. Please try again.';"
//             "      }"
//             "    }"
//             "  });"
//             "});"
//             "</script>";

    size_t buffer_len = *buffer_length;
    char *ptr = buffer;
    char *buffer_end = buffer + buffer_len;

    while (ptr < buffer_end) {
        // Parse chunk size
        char *chunk_size_start = ptr;
        char *chunk_size_end = strstr(ptr, "\r\n");
        if (!chunk_size_end || chunk_size_end >= buffer_end) {
            // Invalid chunked data
            return buffer;
        }

        size_t chunk_size_len = chunk_size_end - chunk_size_start;
        if (chunk_size_len >= 16) {
            // Chunk size too big
            return buffer;
        }

        char chunk_size_str[17];
        memcpy(chunk_size_str, chunk_size_start, chunk_size_len);
        chunk_size_str[chunk_size_len] = '\0';

        // Parse chunk size
        unsigned long chunk_size = strtoul(chunk_size_str, NULL, 16);

        if (chunk_size == 0) {
            // Last chunk (size zero), stop parsing
            break;
        }

        // Move ptr to chunk data
        char *chunk_data_start = chunk_size_end + 2; // Skip \r\n

        if (chunk_data_start + chunk_size + 2 > buffer_end) {
            // Invalid data
            return buffer;
        }

        char *chunk_data_end = chunk_data_start + chunk_size;

        if (chunk_data_end[0] != '\r' || chunk_data_end[1] != '\n') {
            // Invalid chunk ending
            return buffer;
        }

        // Search for </body> in chunk data
        char *body_tag_pos = memmem(chunk_data_start, chunk_size, body_tag, strlen(body_tag));

        if (body_tag_pos != NULL) {
            // Found </body> in this chunk

            // We need to inject the script before </body>

            // Compute positions and lengths
            size_t script_len = strlen(script_to_inject);

            size_t data_before_body_tag_len = body_tag_pos - chunk_data_start;
            size_t data_after_body_tag_len = chunk_data_end - body_tag_pos;

            // New chunk size
            size_t new_chunk_size = chunk_size + script_len;

            // Need to adjust the chunk size field

            // Calculate the new chunk size string length
            char new_chunk_size_str[17];
            int new_chunk_size_str_len = sprintf(new_chunk_size_str, "%lx", new_chunk_size);

            // Calculate difference in chunk size field length
            int old_chunk_size_str_len = chunk_size_len;

            int size_diff = (new_chunk_size_str_len - old_chunk_size_str_len) + script_len;

            // Compute new buffer length
            size_t prefix_len = chunk_size_start - buffer;
            size_t suffix_len = buffer_end - (chunk_data_end + 2);

            size_t new_buffer_length = buffer_len + size_diff;

            // Allocate new buffer
            char *new_buffer = malloc(new_buffer_length);
            if (!new_buffer) {
                return buffer;
            }

            // Copy prefix (before chunk size)
            memcpy(new_buffer, buffer, prefix_len);

            // Write new chunk size
            memcpy(new_buffer + prefix_len, new_chunk_size_str, new_chunk_size_str_len);

            // Write \r\n
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len, "\r\n", 2);

            // Copy data before </body>
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2, chunk_data_start, data_before_body_tag_len);

            // Copy script
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + data_before_body_tag_len, script_to_inject, script_len);

            // Copy data after </body> (includes </body> and trailing \r\n)
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + data_before_body_tag_len + script_len,
                   body_tag_pos, data_after_body_tag_len + 2);

            // Copy suffix
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + new_chunk_size + 2,
                   chunk_data_end + 2, suffix_len);

            // Update buffer_length
            *buffer_length = new_buffer_length;

            printf("Script injected\n");
            // Return new buffer
            return new_buffer;
        }

        // Move to next chunk
        ptr = chunk_data_end + 2; // Move past \r\n
    }

    // </body> not found
    return buffer;
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
