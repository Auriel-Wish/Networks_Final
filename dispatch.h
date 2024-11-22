#include "linked_list.h"
#include "cache.h"

#define BUFFER_SIZE 65536 //64KB

#define CLIENT_FD 0
#define SERVER_FD 1
#define NO_FD_ASSOCIATION 2

bool read_client_request(int client_fd, Node **ssl_contexts, fd_set *active_read_fd_set, int *max_fd, Cache_T *cache);

int client_or_server_fd(Node *ssl_contexts, int fd);

bool handle_connect_request(int fd, Node **ssl_contexts, fd_set *active_read_fd_set, int *max_fd);

void set_max_fd(int new_fd, int *max_fd);

// int get_content_length(char *buff);

// int get_header_length(char *buff);

bool read_server_response(int server_fd, Node **ssl_contexts);

// char *get_content_length_ptr(char *str);

void open_new_conn_to_server(char *hostname, int port, Context_T **curr_context);