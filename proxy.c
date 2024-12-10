#include "dispatch.h"

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
#include <time.h>
#include <assert.h>
#include <signal.h>

#define TIMEOUT ((struct timeval){.tv_sec = TIMEOUT_S, .tv_usec = TIMEOUT_US})
#define TIMEOUT_S 10
#define TIMEOUT_US 0
#define SOCKET_PATH "/tmp/c_dgram_socket"
#define PYTHON_SOCKET_PATH "/tmp/python_dgram_socket"



void client_disconnect(int filedes, Node **ssl_contexts, fd_set *active_read_fd_set, Node **all_messages);

int setup_tcp_server_socket(int portno);

int initialize_LLM_communication(struct sockaddr_un *python_addr);



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

    // Node *all_requests = NULL;
    // Node *all_responses = NULL;
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

                    // printf("Server established connection with %s (%s)\n\n",
                    //  hostp->h_name, hostaddrp);

                    /* Adding new connection request to active socket set */
                    FD_SET(new_fd, &active_read_fd_set);
                    set_max_fd(new_fd, &max_fd);
                }

                else if (client_or_server_fd(ssl_contexts, i) == SERVER_FD) {
                    if (!read_server_response(i, &ssl_contexts, &all_messages)) {
                        client_disconnect(i, &ssl_contexts, &active_read_fd_set, &all_messages);
                    }
                } 
                else {
                    if (!read_client_request(i, &ssl_contexts, &active_read_fd_set, &max_fd, &all_messages, LLM_sockfd, python_addr)) {
                        client_disconnect(i, &ssl_contexts, &active_read_fd_set, &all_messages);
                    }
                }
            }
        }
    }

    return 0;
}

void client_disconnect(int filedes, Node **ssl_contexts, fd_set *active_read_fd_set, Node **all_messages) {
    printf("\n\n\n\n");
    Node *curr = *all_messages;
    while (curr != NULL) {
        incomplete_message *msg = (incomplete_message *)curr->data;
        Node *next = curr->next;
        if (msg->filedes == filedes) {
            // printf("REMOVED IN DISCONNECT\n");
            free(msg->header);
            removeNode(all_messages, msg);
        }
        curr = next;
    }

    // printf("Trying to disconnect a client...");
    FD_CLR(filedes, active_read_fd_set);
    Context_T *curr_context = get_ssl_context_by_client_fd(*ssl_contexts, filedes);
    
    if (curr_context == NULL) {
        curr_context = get_ssl_context_by_server_fd(*ssl_contexts, filedes);
    }

    if (curr_context == NULL) {
        return;
    }

    const char *hostname = SSL_get_servername(curr_context->server_ssl, TLSEXT_NAMETYPE_host_name);
    if (hostname != NULL) {
        char filename[256];
        snprintf(filename, sizeof(filename), "%s.crt", hostname);
        remove(filename);
    }

    FD_CLR(curr_context->client_fd, active_read_fd_set);
    FD_CLR(curr_context->server_fd, active_read_fd_set);

    SSL_set_quiet_shutdown(curr_context->client_ssl, 1);
    SSL_free(curr_context->client_ssl);
    SSL_set_quiet_shutdown(curr_context->client_ssl, 1);
    SSL_free(curr_context->server_ssl);
    close(curr_context->client_fd);
    close(curr_context->server_fd);

    // printf("\nremove node 7\n");

    removeNode(ssl_contexts, curr_context);
    // printf("Successfully disconnected client\n");
}


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
    strncpy(server_addr.sun_path, SOCKET_PATH, 
        sizeof(server_addr.sun_path) - 1);

    // Bind the socket
    unlink(SOCKET_PATH);
    if (bind(sockfd, (struct sockaddr *)&server_addr, 
             sizeof(server_addr)) == -1) 
    {
        perror("Bind failed");
        close(sockfd);
        return -1;
    }

    // Set up the Python client address
    memset(python_addr, 0, sizeof(*python_addr));
    python_addr->sun_family = AF_UNIX;
    strncpy(python_addr->sun_path, PYTHON_SOCKET_PATH, 
        sizeof(python_addr->sun_path) - 1);

    return sockfd;
}