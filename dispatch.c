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
#include <fcntl.h>

#define DECOMPRESSED_BUFFER_SIZE 8192 // Adjust this as needed
#define CHUNK 16384

void set_socket_timeout(int fd, long timeout_millisecs) {
    struct timeval timeout;
    timeout.tv_sec = timeout_millisecs / 1000;           // Whole seconds
    timeout.tv_usec = (timeout_millisecs % 1000) * 1000; // Remainder microsecs
    // Set receive timeout
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set receive timeout");
        fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
    }
    // Set send timeout
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set send timeout");
        fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
    }
}

void set_max_fd(int new_fd, int *max_fd) {
    if (new_fd + 1 > *max_fd) {
        *max_fd = new_fd + 1;
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

SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_server_method(); // Use the TLS server method
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context ");
        ERR_print_errors_fp(stderr);
    }

    return ctx;
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
        
        // Using send instead of write to be robust to client disconnection
        // write(fd, connect_response, strlen(connect_response));
        send(fd, connect_response, strlen(connect_response), MSG_NOSIGNAL);

        // Step 4: Perform SSL handshake with the client after the CONNECT response
        if (SSL_accept(client_ssl) <= 0) {
            printf("\nSSL handshake failed to client\n");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(client_ssl);
            SSL_free(client_ssl);
            close(fd);
            return false;
        }
        // printf("\nSSL handshake with client successful\n");

        // Step 5: Open new connection with the server the client requested
        int port = atoi(strtok(NULL, " "));
        open_new_conn_to_server(hostname, port, &new_context);
        assert(new_context != NULL);

        // NOTE: KNOWN BUG: Sometimes the server cannot be correctly connected
        // to. This creates an issue with the "ERROR, no such host" message
        // appearing many many times

        //assert(new_context->server_ssl != NULL) // will reveal the issue
        append(ssl_contexts, new_context);

        FD_SET(new_context->server_fd, active_read_fd_set);
        set_max_fd(new_context->server_fd, max_fd);

        return true;
    } 
    
    else {
        // Not a CONNECT request
        return false;
    }
}

bool handle_fact_check_request(char *buffer, incomplete_message *curr_message,
    int LLM_sockfd, struct sockaddr_un python_addr, Context_T *curr_context, 
    Node **all_messages)
{
    // If the message is a fact-check request
    printf("Trying to fact-check prematurely, exiting\n");
    assert(false);

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
    printf("Received %d bytes from Python script\n", num_bytes_from_LLM);
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
    printf("Writing Fact check response to client...");
    int write_n = SSL_write(curr_context->client_ssl, fact_check_response_buffer, strlen(fact_check_response_buffer));
    printf("COMPLETE\n");

    // printf("Wrote fact check response to client\n");
    if (write_n <= 0) {
        free(curr_message->header);
        removeNode(all_messages, curr_message);
        return false;
    }
}

bool handle_general_client_request(incomplete_message *curr_message, int read_n, 
    Context_T *curr_context, Node **all_messages, char *buffer) {
        // If the message is a regular client request
    int write_n = 0;
    curr_message->content_length_read += read_n;
    if (!(curr_message->header_sent) && curr_message->header_complete) {
        int header_length = strlen(curr_message->header);

        // printf("Writing message header to server...");
        write_n = SSL_write(curr_context->server_ssl, curr_message->header, header_length);
        // printf("COMPLETE\n");


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

            // printf("Writing normal message  contetn to client...");
            write_n = SSL_write(curr_context->server_ssl, buffer, read_n);
            // printf("COMPLETE\n");


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

    return true;
}

bool read_client_request(int client_fd, Node **ssl_contexts, 
    fd_set *active_read_fd_set, int *max_fd, Cache_T *cache, Node **all_messages, int LLM_sockfd, struct sockaddr_un python_addr) {
    Context_T *curr_context = get_ssl_context_by_client_fd(*ssl_contexts, client_fd);
    (void)cache;
    
    if (curr_context == NULL) {
        /* No SSL Context associated with this file descriptor 
         * read HTTP CONNECT (should be a connect)
         * setup SSL connection, adds to FD -> SSL mapping */
        return handle_connect_request(client_fd, ssl_contexts, active_read_fd_set, max_fd);
    }
    
    else {
        /* Client already securely connected, reading in a request */
        
        // Step 1: Read existing request
        char buffer_arr[BUFFER_SIZE];
        char *buffer = buffer_arr;
        int read_n;

        read_n = SSL_read(curr_context->client_ssl, buffer, BUFFER_SIZE);

        if (read_n <= 0) {
            // Failed to read in anything
            int ssl_error = SSL_get_error(curr_context->client_ssl, read_n);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                return true; // Keep the connection open
            } else {
                return false; // Close the connection
            }
        }
        
        else { // if (read_n > 0)
            // Step 2: Get any incomplete message already associated with that client
            incomplete_message *curr_message = 
                get_incomplete_message_by_filedes(*all_messages, 
                    curr_context->client_fd);
            curr_message = modify_header_data(&curr_message, buffer, 
                curr_context->client_fd, all_messages);

            // Step 3: See if the message is a fact-check request from the 
            // client, or a different request
            char *fact_check = strstr(curr_message->header, 
                "fact-check-CS112-Final");
            if (fact_check != NULL) {
                return handle_fact_check_request(buffer, curr_message, 
                    LLM_sockfd, python_addr, curr_context, all_messages);
            }

            else {
                return handle_general_client_request(curr_message, read_n, 
                    curr_context, all_messages, buffer);
            }
        }
    }
}

bool read_server_response(int server_fd, Node **ssl_contexts, Node **all_messages) {
    Context_T *curr_context = get_ssl_context_by_server_fd(*ssl_contexts, server_fd);
    if (curr_context == NULL) { return false; }

    // printf("Trying to get data from hostname: %s\n", curr_context->hostname);
    bool at_quora = (strcmp("www.quora.com", curr_context->hostname) == 0);
    if (at_quora) {
        // printf("Getting ready to search quora\n");
    }

    char buffer_arr[BUFFER_SIZE];
    char *buffer = buffer_arr;
    int read_n = SSL_read(curr_context->server_ssl, buffer, BUFFER_SIZE);

    int write_n;

    if (read_n <= 0) {
        int ssl_error = SSL_get_error(curr_context->server_ssl, read_n);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            return true; // Retry the operation later, keep the connection open
        } else {
            return false; // Close the connection
        }
    }

    else { //if (read_n > 0)
        incomplete_message *curr_message = get_incomplete_message_by_filedes(*all_messages, curr_context->server_fd);
        curr_message = modify_header_data(&curr_message, buffer, curr_context->server_fd, all_messages);            

        curr_message->content_length_read += read_n;
        
        // If the response header hasn't been sent to the client yet, send it
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

        // If there are more bytes to be sent in the response
        if (read_n > 0) {

            // Weird encoding???
            if (curr_message->original_content_type != NORMAL_ENCODING) {
                // printf("original_content_type: %d\n", curr_message->original_content_type);
                
                // TODO: Only try to do injection if we're at quora
                // Injection
                int to_send_length = read_n;
                char *to_send = inject_script_into_chunked_html(buffer, &to_send_length);

                // maybe the injection could be the issue?
                // printf("Injection with normal encoding...");
                write_n = SSL_write(curr_context->client_ssl, to_send, to_send_length);
                // printf("COMPLETE\n");

                // No injection
                // write_n = SSL_write(curr_context->client_ssl, buffer, read_n);

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

            else { // content_type == NORMAL_ENCODING

                int chunk_data_length = 0;
                char *chunked_data = convert_to_chunked_encoding(buffer, read_n, curr_message, &chunk_data_length);

                if (chunked_data == NULL) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                    return false;
                }

                // TODO: only try to do injection if we're at quora
                // Injection
                int to_send_length = chunk_data_length;
                char *to_send = inject_script_into_chunked_html(chunked_data, &to_send_length);

                // printf("Injection with chunked encoding...");
                write_n = SSL_write(curr_context->client_ssl, to_send, to_send_length);
                // printf("COMPLETE\n");
                
                // No injection
                // write_n = SSL_write(curr_context->client_ssl, chunked_data, chunk_data_length);
                
                if (write_n <= 0) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                    return false;
                }

                if (curr_message->content_length_read >= curr_message->content_length) {
                    free(curr_message->header);
                    removeNode(all_messages, curr_message);
                }
            }


        }

        return true;
    }
}


// // Old version

/*
bool read_server_response(int server_fd, Node **ssl_contexts, Node **all_messages) {
    Context_T *curr_context = get_ssl_context_by_server_fd(*ssl_contexts, server_fd);
    if (curr_context == NULL) { return false; }

    char buffer_arr[BUFFER_SIZE];
    char *buffer = buffer_arr;
    int read_n = SSL_read(curr_context->server_ssl, buffer, BUFFER_SIZE);

    int write_n;

    if (read_n <= 0) {
        int ssl_error = SSL_get_error(curr_context->server_ssl, read_n);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            return true; // Retry the operation later, keep the connection open
        } else {
            return false; // Close the connection
        }
    }

    else { //if (read_n > 0)
        incomplete_message *curr_message = get_incomplete_message_by_filedes(*all_messages, curr_context->server_fd);
        curr_message = modify_header_data(&curr_message, buffer, curr_context->server_fd, all_messages);            

        curr_message->content_length_read += read_n;
        
        // If the response header hasn't been sent to the client yet, send it
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

        // If there are more bytes to be sent in the response
        if (read_n > 0) {

            // Weird encoding???
            if (curr_message->original_content_type != NORMAL_ENCODING) {
                // printf("original_content_type: %d\n", curr_message->original_content_type);
                
                // Injection
                int to_send_length = read_n;
                char *to_send = inject_script_into_chunked_html(buffer, &to_send_length);

                // maybe the injection could be the issue?
                // printf("Injection with normal encoding...");
                write_n = SSL_write(curr_context->client_ssl, to_send, to_send_length);
                // printf("COMPLETE\n");

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

            // Normal encoding
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

                // printf("Injection with chunked encoding...");
                write_n = SSL_write(curr_context->client_ssl, to_send, to_send_length);
                // printf("COMPLETE\n");
                
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
}
*/