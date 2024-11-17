#include "linked_list.h"

#define BUFFER_SIZE 4096
#define GET_REQUEST 1
#define CONNECT_REQUEST 0
#define POST_REQUEST 2

typedef struct {
    int placeholder;
    char *buffer;
    unsigned size;
} Dispatch_T;

// typedef struct __attribute__((__packed__)) {
//     uint32_t size_of_request;
//     char *hostname;
//     int portno;
//     char *request_string;
// } HTTPS_REQ_T;

Dispatch_T* new_dispatch();

void free_dispatch(Dispatch_T **dispatch);

client_request *read_new_client_request(int fd, Node **ssl_contexts, Context_T *curr_context);

void respond_to_client(server_response *res, Node *ssl_contexts);

void get_post_request_data_size(client_request **request, char *buffer);

void read_existing_incomplete_client_request(client_request **incomplete_request, Context_T *curr_context);

bool req_is_complete(client_request *req);

void send_request_to_cache(client_request *req, int cache_fd, int port, struct sockaddr_un *cache_server_addr, socklen_t cache_server_len);

char *read_server_response(int cache_fd, struct sockaddr_un *cache_server_addr, socklen_t *cache_server_len);

server_response *read_new_server_response(char *response_string);

void get_response_content_length(server_response **response);

void read_existing_server_response(server_response **existing_response, char *next_part_of_response_string);

bool server_response_is_complete(server_response *response);

char *get_content_length_ptr(char *str);