#include "dispatch.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

#define BUFSIZE 1024

typedef struct {
    char *buf;
    int size;
} Buffer_T;

void error(char *msg)
{
    perror(msg);
    exit(0);
}

Buffer_T *new_Buffer_T(char *buf, int size)
{
    Buffer_T *buffer = malloc(sizeof(Buffer_T));
    buffer->buf = buf;
    buffer->size = size;

    return buffer;
}

Dispatch_T* new_dispatch()
{
    Dispatch_T *dispatch = malloc(sizeof(Dispatch_T));
    assert(dispatch != NULL);

    dispatch->placeholder = 0;
    dispatch->buffer = NULL;
    dispatch->size = 0;

    return dispatch;
}

void free_dispatch(Dispatch_T **dispatch)
{
    free(*dispatch);
    *dispatch = NULL;
}

Buffer_T *read_get_request(int childfd)
{
    char ch;
    int status;
    int i = 0;
    bool prior_CRLF = false;

    // NOTE: I'm going to allocate the buffer on the heap here.
    // Using calloc to initialize every slot to 0
    char *buf = calloc(BUFSIZE, sizeof(char));
    unsigned long capacity = BUFSIZE;
    unsigned long old_capacity = BUFSIZE;

    // GET requests must be less than BUFSIZE right now
    while (true)
    {
        if (i == capacity - 1) {
            // if at capacity, expand the buffer
            old_capacity = capacity;
            capacity *= 2;
            char *new_buf = calloc(capacity, sizeof(char));
            for (int j = 0; j < old_capacity; j++) {
                new_buf[j] = buf[j];
            }

            free(buf);
            buf = new_buf;
        }

        status = read(childfd, &ch, 1);

        if (status < 0)
            error("ERROR reading from socket");

        buf[i] = ch;
        i++;

        if (ch == '\r')
        {
            status = read(childfd, &ch, 1);
            buf[i] = ch;
            i++;

            if (ch == '\n')
            {
                if (prior_CRLF)
                {
                    // two carriage returns in a row means end of request
                    // printf("\nRequest completed\n");
                    break;
                }

                prior_CRLF = true;
            }
            else
            {
                printf("Bad formatting\n");
            }
        }
        else
        {
            prior_CRLF = false;
        }
    }

    printf("Proxy received %d bytes: \n\n%s\n\n", i, buf);
    Buffer_T *buffer = new_Buffer_T(buf, i);

    return buffer;
}


HTTPS_REQ_T* read_client_request(int fd)
{
    // need to read in the client request

    /* This step could be super difficult because we need to pretend to be our
     * own SSL certificate. For now, we will keep it simple by hardcoding the
     * HTTPS request in the buffer */

    Buffer_T *incoming = read_get_request(fd);
    (void)incoming;


    // if client disconnects, return NULL
    HTTPS_REQ_T *req = malloc(sizeof(HTTPS_REQ_T));
    assert(req != NULL);

    /* The HTTPS request is currently hardcoded here. Once we successfully can
     * communicate with the client via HTTPS, we will change this */
    char *msg = "GET / HTTP/1.1\r\nHost: {google.com}\r\nConnection: close\r\n\r\n";
    char *hostname = "google.com";
    char *port = "443";
    char *request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";

    req->raw = strdup(msg);
    req->size = strlen(msg);
    req->hostname = strdup(hostname);
    req->portno = strdup(port);
    req->request = strdup(request);

    return req;
}

void respond_to_client()
{
    printf("Responding to the client\n");
}