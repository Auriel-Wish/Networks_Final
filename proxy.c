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
#include "dispatch.h"
#include "fetch.h"

char *get_cache_result(HTTPS_REQ_T *req, struct sockaddr_in serveraddr);

#define TIMEOUT ((struct timeval){.tv_sec = TIMEOUT_S, .tv_usec = TIMEOUT_US})
#define TIMEOUT_S 3
#define TIMEOUT_US 0
#define BUFFER_SIZE 4096 // too small?

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


    /* Initialize the set of active sockets */
    FD_ZERO (&active_fd_set);
    FD_SET (parentfd, &active_fd_set);

    struct sockaddr_in clientaddr;

    Dispatch_T *dispatch = new_dispatch();

    while (true) {
        read_fd_set = active_fd_set;

        /* SELECT will timeout when the next buffered message expires */
        if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, &TIMEOUT) < 0) {
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

                    /* Adding new connection request to active socket set */
                    FD_SET(new_fd, &active_fd_set);
                }

                else {
                    /* Incoming data from already-connected socket */
                    HTTPS_REQ_T *req = read_client_request(i);

                    char *response;
                    response = get_cache_result(req, serveraddr);
        
                    /* If cache content is valid, serve it to the client */
                    if (response != NULL) {
                        respond_to_client();
                    }

                    char *hostname = "google.com";
                    char *port = "443";
                    char *request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";

                    /* Else, fetch from the actual webpage */
                    response = fetch(hostname, port, request);

                    /* then return the response to the client */
                    respond_to_client();

                    /* Only close the socket if we reach EOF (the client
                     * closes the connection) */
                    // if (n < 0) {
                    if (req == NULL) {
                        close(i);
                        FD_CLR(i, &active_fd_set);
                    }
                }
            }
        }
    }

    free_dispatch(&dispatch);

    return 0;
}

char *get_cache_result(HTTPS_REQ_T *req, struct sockaddr_in serveraddr) {
    socklen_t addr_len = sizeof(serveraddr);
    
    char *temp_buff = req->buf;

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("Sending message to server: %s\n", temp_buff);
    if (sendto(sockfd, temp_buff, strlen(temp_buff), 0, (struct sockaddr*)&serveraddr, addr_len) < 0) {
        perror("Send failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    char buffer[BUFFER_SIZE];
    int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&serveraddr, &addr_len);
    if (n < 0) {
        perror("Receive failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (strcmp("NULL", buffer) == 0) {
        return NULL;
    }
    else {
        char *cache_data = (char *)malloc(n + 1);
        memcpy(cache_data, buffer, n);
        cache_data[n] = '\0';
        return cache_data;
    }
}