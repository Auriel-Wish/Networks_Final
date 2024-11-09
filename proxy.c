#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUF_TTL 3

int main(int argc, char **argv)
{
    int portno;
    int parentfd;

    struct sockaddr_in serveraddr;
    struct hostent *hostp;
    char *hostaddrp;

    fd_set active_fd_set, read_fd_set;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    portno = atoi(argv[1]);
    printf("Listening on port %d\n", portno);

    parentfd = socket(AF_INET, SOCK_STREAM, 0);
    if (parentfd < 0) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval, sizeof(int));

    // build the server's internet address
    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)portno);

    // bind the parent socket to the input portno
    if (bind(parentfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
        perror("Error on binding");

    if (listen(parentfd, 0) < 0)
        perror("Error on listen");


    /* Initialize the set of active sockets */
    FD_ZERO (&active_fd_set);
    FD_SET (parentfd, &active_fd_set);

    struct sockaddr_in clientaddr;

    // Dispatch_T *dispatch = new_dispatch();

    struct timeval timeout;
    timeout.tv_sec = BUF_TTL;    //setting the default timeout
    timeout.tv_usec = 0;

    while (true) {
        /* Try to free any buffers older than the TTL
         * If a buffer is freed, the client is removed from the list and their
         * connection is closed */
        // free_old_buffers(dispatch->table, &active_fd_set, dispatch->clients);

        /* For the remaining buffered content, return the time until the next
         * one will expire */
        // timeout = get_next_timeout(dispatch->table);
        printf("rerunning select in %ld seconds\n", timeout.tv_sec);

        read_fd_set = active_fd_set;

        /* SELECT will timeout when the next buffered message expires */
        if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout) < 0) {
            perror("ERROR with select");
        }

        /* Service all sockets with input pending */
        for (int i = 0; i < FD_SETSIZE; ++i) {
            if (FD_ISSET (i, &read_fd_set)) {
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

                    // Adding the new connection request to the set of active
                    // sockets
                    FD_SET(new_fd, &active_fd_set);

                    /* The client socket has connected with the current socket, 
                     * but the client has not identified itself yet. Therefore, 
                     * as of right now, it's not in the list of active clients
                     * even though it's in the set of FDs */
                }

                else {
                    /* Incoming data from already-connected socket */
                    // int n = read_message(i, dispatch);
                    int n = 0;

                    /* Only close the socket if we reach EOF (the client
                     * closes the connection) */
                    if (n < 0) {
                        close(i);
                        FD_CLR(i, &active_fd_set);
                    }
                }
            }
        }
    }

    // free_dispatch(&dispatch);

    return 0;
}