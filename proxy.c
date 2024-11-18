#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/un.h>
#include "dispatch.h"
#include <time.h>
#include <assert.h>

#define TIMEOUT ((struct timeval){.tv_sec = TIMEOUT_S, .tv_usec = TIMEOUT_US})
#define TIMEOUT_S 3
#define TIMEOUT_US 0
#define BUFFER_SIZE 4096

#define CACHE_PORT 1025

void client_disconnect(int client_filedes, Node **ssl_contexts, Node **client_requests, Node **server_responses, fd_set *active_read_fd_set, fd_set *active_write_fd_set);



int setup_tcp_server_socket(int portno) {
    struct sockaddr_in serveraddr;
    
    int parentfd = socket(AF_INET, SOCK_STREAM, 0);
    if (parentfd < 0) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval, sizeof(int));

    /* build the server's internet address */
    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)portno);

    /* bind the parent socket to the input portno */
    if (bind(parentfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
        perror("Error on binding");

    if (listen(parentfd, 0) < 0)
        perror("Error on listen");
    
    return parentfd;
}



int main(int argc, char **argv)
{
    int portno;

    struct hostent *hostp;
    char *hostaddrp;

    fd_set active_read_fd_set, read_fd_set, active_write_fd_set, write_fd_set;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    portno = atoi(argv[1]);
    printf("Proxy listening on port %d\n", portno);
    
    int parentfd = setup_tcp_server_socket(portno);

    /* Initialize the set of active sockets */
    FD_ZERO(&active_read_fd_set);
    FD_SET(parentfd, &active_read_fd_set);


    FD_ZERO(&active_write_fd_set);

    // NOTE: Ignore the cache for now
    int cache_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (cache_fd < 0) {
        perror("Error creating UNIX socket");
        return -1;
    }

    struct sockaddr_un cache_server_addr, cache_client_addr;
    memset(&cache_client_addr, 0, sizeof(cache_client_addr));
    cache_client_addr.sun_family = AF_UNIX;
    strncpy(cache_client_addr.sun_path, "/tmp/cache_client.sock", sizeof(cache_client_addr.sun_path) - 1);
    unlink(cache_client_addr.sun_path);
    if (bind(cache_fd, (struct sockaddr *)&cache_client_addr, sizeof(cache_client_addr)) < 0) {
        perror("Error binding client socket");
        close(cache_fd);
        exit(EXIT_FAILURE);
    }

    memset(&cache_server_addr, 0, sizeof(cache_server_addr));
    cache_server_addr.sun_family = AF_UNIX;
    strncpy(cache_server_addr.sun_path, "/tmp/cache_server.sock", sizeof(cache_server_addr.sun_path) - 1);
    socklen_t cache_server_len = sizeof(cache_client_addr);

    FD_SET(cache_fd, &active_read_fd_set);

    struct sockaddr_in clientaddr;

    Dispatch_T *dispatch = new_dispatch();

    Node *ssl_contexts = NULL;
    Node *client_requests = NULL;
    Node *server_responses = NULL;

    while (true) {
        read_fd_set = active_read_fd_set;
        write_fd_set = active_write_fd_set;

        // print_fd_set(&write_fd_set, "write_fd_set");

        /* SELECT will timeout when the next buffered message expires */
        if (select (FD_SETSIZE, &read_fd_set, &write_fd_set, NULL, &TIMEOUT) < 0) {
            perror("ERROR with select");
        }

        /* Service all sockets with input pending */
        for (int i = 0; i < FD_SETSIZE; ++i) {
            if (FD_ISSET(i, &read_fd_set)) {
                
                if (i == parentfd) {
                    /* Connection request on parent socket */
                    int new_fd;
                    socklen_t size = sizeof(clientaddr);
                    new_fd = accept(parentfd, (struct sockaddr *)&clientaddr, 
                        &size);

                    if (new_fd < 0) {
                        perror("Error accepting new socket");
                    }

                    /* gethostbyaddr: determine who sent the message */
                    hostp = gethostbyaddr(
                        (const char *)&clientaddr.sin_addr.s_addr,
                        sizeof(clientaddr.sin_addr.s_addr), 
                        AF_INET
                    );

                    if (hostp == NULL) {
                        perror("ERROR on gethostbyaddr");
                    }

                    hostaddrp = inet_ntoa(clientaddr.sin_addr);
                    if (hostaddrp == NULL) {
                        perror("Error on inet_ntoa");
                    }

                    printf("Server established connection with %s (%s)\n\n",
                        hostp->h_name, hostaddrp);

                    /* Adding new connection request to active socket set */
                    FD_SET(new_fd, &active_read_fd_set);
                }

                else if (i == cache_fd) {
                    /* Message coming from cache */
                    //NOTE: intentionally broken for now
                    // assert(false);

                    char *buffer = read_server_response(cache_fd, &cache_server_addr, &cache_server_len);
                    int client_filedes = buffer[0];
                    char *response_string = buffer + 1;

                    server_response *incomplete_response = get_server_response(server_responses, client_filedes);
                    if (incomplete_response == NULL) {
                        incomplete_response = read_new_server_response(response_string);
                        incomplete_response->filedes = client_filedes;
                        append(&server_responses, incomplete_response);
                    }
                    
                    else {
                        read_existing_server_response(&incomplete_response, response_string);
                    }

                    if (server_response_is_complete(incomplete_response)) {
                        incomplete_response->response_complete = true;
                        FD_SET(client_filedes, &active_write_fd_set);
                    }
                }

                else {
                    /* Message coming from connected client */
                    Context_T *curr_context = get_ssl_context(ssl_contexts, i);

                    if (curr_context == NULL) {
                        client_request *incomplete_request = read_new_client_request(i, &ssl_contexts, curr_context);
                        if (incomplete_request != NULL && incomplete_request->filedes == -1) {
                            client_disconnect(i, &ssl_contexts, &client_requests, &server_responses, &active_read_fd_set, &active_write_fd_set);
                        }
                    }

                    else {

                        // Trying here
                        client_request *incomplete_request = get_client_request(client_requests, i);

                        if (incomplete_request == NULL) {
                            incomplete_request = read_new_client_request(i, &ssl_contexts, curr_context);
                            append(&client_requests, incomplete_request);
                            if (incomplete_request != NULL && incomplete_request->filedes == -1) {
                                client_disconnect(i, &ssl_contexts, &client_requests, &server_responses, &active_read_fd_set, &active_write_fd_set);
                            }
                        }
                        else {
                            read_existing_incomplete_client_request(&incomplete_request, curr_context);
                        }


                        if (req_is_complete(incomplete_request)) {
                            incomplete_request->request_complete = true;
                            FD_SET(cache_fd, &active_write_fd_set);
                        }


                    }
                }
            }

            if (FD_ISSET(i, &write_fd_set)) {
                if (i == cache_fd) {
                    for (Node *curr = client_requests; curr != NULL; curr = curr->next) {
                        assert(curr != NULL);
                        client_request *curr_request = curr->data;
                        if (curr_request->request_complete) {
                            int client_filedes = curr_request->filedes;
                            Context_T *curr_context = get_ssl_context(ssl_contexts, client_filedes);
                            int curr_port = curr_context->port;
                            send_request_to_cache(curr_request, cache_fd, curr_port, &cache_server_addr, cache_server_len);
                            // free(curr_request->request_string);
                            removeNode(&client_requests, curr_request);
                            curr_request = NULL;
                        }
                    }
                    
                    bool should_clear = true;
                    for (Node *curr = client_requests; curr != NULL; curr = curr->next) {
                        client_request *curr_request = curr->data;
                        if (curr_request->request_complete) {
                            should_clear = false;
                            break;
                        }
                    }
                    if (should_clear) {
                        FD_CLR(i, &active_write_fd_set);
                    }
                }
                else {
                    for (Node *curr = server_responses; curr != NULL; curr = curr->next) {
                        server_response *curr_response = curr->data;
                        if (curr_response->response_complete && curr_response->filedes == i) {
                            respond_to_client(curr_response, ssl_contexts);
                            free(curr_response->response_string);
                            removeNode(&server_responses, curr_response);
                            curr_response = NULL;
                            FD_CLR(i, &active_write_fd_set);
                            break;
                        }
                    }
                }
            }
        }
    }

    free_dispatch(&dispatch);

    return 0;
}

void client_disconnect(int client_filedes, Node **ssl_contexts, Node **client_requests, Node **server_responses, fd_set *active_read_fd_set, fd_set *active_write_fd_set) {
    fprintf(stderr, "DISCONNECTING THE CLIENT\n");
    Context_T *curr_context = get_ssl_context(*ssl_contexts, client_filedes);
    SSL_shutdown(curr_context->ssl);
    close(client_filedes);
    removeNode(ssl_contexts, curr_context);

    for (Node *curr = *client_requests; curr != NULL; curr = curr->next) {
        client_request *curr_request = curr->data;
        if (curr_request->filedes == client_filedes) {
            free(curr_request->request_string);
            removeNode(client_requests, curr_request);
        }
    }

    for (Node *curr = *server_responses; curr != NULL; curr = curr->next) {
        server_response *curr_response = curr->data;
        if (curr_response->filedes == client_filedes) {
            free(curr_response->response_string);
            removeNode(server_responses, curr_response);
        }
    }

    FD_CLR(client_filedes, active_read_fd_set);
    FD_CLR(client_filedes, active_write_fd_set);
}