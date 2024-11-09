#include "dispatch.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

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

HTTPS_REQ_T* read_client_request(int fd)
{
    // need to read in the client request

    /* This step could be super difficult because we need to pretend to be our
     * own SSL certificate. For now, we will keep it simple by hardcoding the
     * HTTPS request in the buffer */

    // if client disconnects, return NULL
    HTTPS_REQ_T *req = malloc(sizeof(HTTPS_REQ_T));
    assert(req != NULL);

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