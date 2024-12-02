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
#define TIMEOUT_S 10
#define TIMEOUT_US 0

void client_disconnect(int client_filedes, Node **ssl_contexts, fd_set *active_read_fd_set);

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
    int max_fd = 0;

    struct hostent *hostp;
    char *hostaddrp;

    fd_set active_read_fd_set, read_fd_set;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    portno = atoi(argv[1]);
    printf("Proxy listening on port %d\n", portno);
    
    int parentfd = setup_tcp_server_socket(portno);

    struct sockaddr_in clientaddr;

    Node *ssl_contexts = NULL;

    Cache_T *cache = create_cache(20); // setting capacity to be small for now
    (void)cache;

    /* Initialize the set of active sockets */
    FD_ZERO(&active_read_fd_set);
    FD_SET(parentfd, &active_read_fd_set);
    set_max_fd(parentfd, &max_fd);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    while (true) {
        read_fd_set = active_read_fd_set;

        // fprintf(stderr, "SELECT blocking...");

        if (select(max_fd, &read_fd_set, NULL, NULL, &TIMEOUT) < 0) {
            perror("ERROR with select");
            continue;
        }

        // fprintf(stderr, "DONE blocking\n");

        /* Service all sockets with input pending */
        for (int i = 0; i < max_fd; ++i) {
            // printf("Checking socket %d\n", i);
            /* READING sockets */
            if (FD_ISSET(i, &read_fd_set)) {
                if (i == parentfd) {
                    /* CONNECTION request on parent socket */
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

                    // printf("Server established connection with %s (%s)\n\n", hostp->h_name, hostaddrp);

                    /* Adding new connection request to active socket set */
                    FD_SET(new_fd, &active_read_fd_set);
                    set_max_fd(new_fd, &max_fd);
                }

                // Couldn't this be an issue if there were multiple servers 
                // that we were connected to at the same time?

                else if (client_or_server_fd(ssl_contexts, i) == SERVER_FD) {
                    // printf("\nReading from server: %d\n", i);
                    if (!read_server_response(i, &ssl_contexts)) {
                        client_disconnect(i, &ssl_contexts, &active_read_fd_set);
                    }
                } 
                
                else {
                    // printf("\nReading from client %d\n", i);
                    if (!read_client_request(i, &ssl_contexts, &active_read_fd_set, &max_fd, NULL)) {
                        client_disconnect(i, &ssl_contexts, &active_read_fd_set);
                    }
                }

                // else {
                    //if (client_or_server_fd(ssl_contexts, i) == CLIENT_FD)
                //     // fprintf(stderr, "No fd association\n");
                //     // assert(false);
                // }

            }
        }
    }

    return 0;
}

void client_disconnect(int filedes, Node **ssl_contexts, fd_set *active_read_fd_set) {
    // fprintf(stderr, "DISCONNECTING THE CLIENT: %d...", filedes);

    FD_CLR(filedes, active_read_fd_set);
    Context_T *curr_context = get_ssl_context_by_client_fd(*ssl_contexts, filedes);
    
    if (curr_context == NULL) {
        curr_context = get_ssl_context_by_server_fd(*ssl_contexts, filedes);
    }

    if (curr_context == NULL) {
        // printf("No context found for file descriptor %d\n", filedes);
        return;
    }

    const char *hostname = SSL_get_servername(curr_context->server_ssl, TLSEXT_NAMETYPE_host_name);
    if (hostname != NULL) {
        char filename[256];
        snprintf(filename, sizeof(filename), "%s.crt", hostname);
        remove(filename);
        // if (remove(filename) == 0) {
        //     printf("Deleted certificate file: %s\n", filename);
        // } else {
        //     printf("Error deleting certificate file");
        // }
    }

    FD_CLR(curr_context->client_fd, active_read_fd_set);
    FD_CLR(curr_context->server_fd, active_read_fd_set);

    SSL_shutdown(curr_context->client_ssl);
    SSL_free(curr_context->client_ssl);
    SSL_shutdown(curr_context->server_ssl);
    SSL_free(curr_context->server_ssl);
    close(curr_context->client_fd);
    close(curr_context->server_fd);

    removeNode(ssl_contexts, curr_context);

    // fprintf(stderr, " COMPLETE\n");
}