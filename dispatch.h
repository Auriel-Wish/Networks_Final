#include "linked_list.h"

typedef struct {
    int placeholder;
    char *buffer;
    unsigned size;
} Dispatch_T;

typedef struct {
    unsigned size;

    char *hostname;
    char *portno;
    char *request;
} HTTPS_REQ_T;

Dispatch_T* new_dispatch();

void free_dispatch(Dispatch_T **dispatch);

HTTPS_REQ_T* read_client_request(int fd, Node *front);

void respond_to_client();