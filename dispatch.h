#include "linked_list.h"

#define BUFFER_SIZE 4096

typedef struct {
    int placeholder;
    char *buffer;
    unsigned size;
} Dispatch_T;

typedef struct __attribute__((__packed__)) {
    uint32_t size_of_request;
    char *hostname;
    int portno;
    char *request_string;
} HTTPS_REQ_T;

Dispatch_T* new_dispatch();

void free_dispatch(Dispatch_T **dispatch);

HTTPS_REQ_T* read_client_request(int fd, Node **front);

void respond_to_client();