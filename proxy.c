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
#define SOCKET_PATH "/tmp/c_dgram_socket"
#define PYTHON_SOCKET_PATH "/tmp/python_dgram_socket"

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

int initialize_LLM_communication(struct sockaddr_un *python_addr) {
    int sockfd;

    // Create a Unix domain datagram socket
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        return -1;
    }

    // Set up the server address
    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Bind the socket
    unlink(SOCKET_PATH);
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(sockfd);
        return -1;
    }

    // Set up the Python client address
    memset(python_addr, 0, sizeof(*python_addr));
    python_addr->sun_family = AF_UNIX;
    strncpy(python_addr->sun_path, PYTHON_SOCKET_PATH, sizeof(python_addr->sun_path) - 1);

    return sockfd;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
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

    struct sockaddr_un python_addr;
    // socklen_t python_addr_len;
    int LLM_sockfd = initialize_LLM_communication(&python_addr);

    struct sockaddr_in clientaddr;

    Node *ssl_contexts = NULL;

    /* Initialize the set of active sockets */
    FD_ZERO(&active_read_fd_set);
    FD_SET(parentfd, &active_read_fd_set);
    set_max_fd(parentfd, &max_fd);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    Node *all_messages = NULL;

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
                    if (!read_server_response(i, &ssl_contexts, &all_messages)) {
                        client_disconnect(i, &ssl_contexts, &active_read_fd_set);
                    }
                } 
                
                else {
                    if (!read_client_request(i, &ssl_contexts, &active_read_fd_set, &max_fd, &all_messages, LLM_sockfd, python_addr)) {
                        client_disconnect(i, &ssl_contexts, &active_read_fd_set);
                    }
                }
            }
        }
    }

    return 0;
}

void client_disconnect(int filedes, Node **ssl_contexts, fd_set *active_read_fd_set) {
    // printf("Disconnecting: %d\n", filedes);
    FD_CLR(filedes, active_read_fd_set);
    Context_T *curr_context = get_ssl_context_by_client_fd(*ssl_contexts, filedes);
    
    if (curr_context == NULL) {
        curr_context = get_ssl_context_by_server_fd(*ssl_contexts, filedes);
    }

    // printf("\na\n");

    if (curr_context == NULL) {
        return;
    }
    // printf("\nb\n");


    const char *hostname = SSL_get_servername(curr_context->server_ssl, TLSEXT_NAMETYPE_host_name);
    if (hostname != NULL) {
        char filename[256];
        snprintf(filename, sizeof(filename), "%s.crt", hostname);
        remove(filename);
    }

    FD_CLR(curr_context->client_fd, active_read_fd_set);
    FD_CLR(curr_context->server_fd, active_read_fd_set);
    // printf("\nc\n");

    // struct timeval timeout;
    // timeout.tv_sec = 0;  // No timeout
    // timeout.tv_usec = 0;

    // if (setsockopt(filedes, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    //     perror("Failed to set receive timeout");
    //     fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
    // }
    // if (setsockopt(filedes, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
    //     perror("Failed to set send timeout");
    //     fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
    // }


    // SSL_shutdown(curr_context->client_ssl);
    // printf("\nc1\n");
    SSL_free(curr_context->client_ssl);
    // printf("\nc2\n");
    // SSL_shutdown(curr_context->server_ssl);
    // printf("\nc3\n");
    SSL_free(curr_context->server_ssl);
    // printf("\nc4\n");
    close(curr_context->client_fd);
    // printf("\nc5\n");
    close(curr_context->server_fd);
    // printf("\nd\n");


    removeNode(ssl_contexts, curr_context);
    // printf("\ne\n");


    // printf("Disconnected: %d\n", filedes);
}