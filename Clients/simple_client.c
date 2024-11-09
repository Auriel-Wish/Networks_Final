#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUFSIZE 1024

#define IP "10.4.2.20"
#define PORT 9052

void error(char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char **argv)
{
    int sockfd, portno, n;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;

    /* check command line arguments */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        exit(0);
    }

    hostname = IP;
    portno = PORT;

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host as %s\n", hostname);
        exit(0);
    }

    /* build the server's Internet address */
    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    /* connect: create a connection with the server */
    if (connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
        error("ERROR connecting");

    char buf[BUFSIZE];
    char *hello = "Sending a really simple message\n";

    n = write(sockfd, hello, strlen(hello));
    if (n < 0)
        error("ERROR writing to socket");

    /* print the server's reply */
    bzero(buf, 450);
    n = 1;

    //until we read 0 bytes, keep reading
    while (n > 0) {
        n = read(sockfd, buf, 450);
        printf("Read %d bytes\n", n);
    }

    if (n < 0)
        error("ERROR reading from socket");
   
    close(sockfd);
    return 0;
}