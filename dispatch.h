#include "linked_list.h"
#include "cache.h"

#define BUFFER_SIZE 65536 //64KB

#define CLIENT_FD 0
#define SERVER_FD 1
#define NO_FD_ASSOCIATION 2

#define NORMAL_ENCODING -3
#define CHUNKED_ENCODING -2

// Parser states
enum {
    CHUNK_SIZE,
    CHUNK_SIZE_LF,
    CHUNK_DATA,
    CHUNK_DATA_CR,
    CHUNK_DATA_LF,
    CHUNK_DONE
};

bool read_client_request(int client_fd, Node **ssl_contexts, fd_set *active_read_fd_set, int *max_fd, Cache_T *cache, Node **all_messages, int LLM_sockfd, struct sockaddr_un python_addr);

int client_or_server_fd(Node *ssl_contexts, int fd);

bool handle_connect_request(int fd, Node **ssl_contexts, fd_set *active_read_fd_set, int *max_fd);

void set_max_fd(int new_fd, int *max_fd);

// int get_content_length(char *buff);

// int get_header_length(char *buff);

bool read_server_response(int server_fd, Node **ssl_contexts, Node **all_messages);

char *get_content_length_ptr(char *str);

void open_new_conn_to_server(char *hostname, int port, Context_T **curr_context);

void print_buffer(unsigned char *m, unsigned size);

message *insert_new_data(message **msg, char *buffer, int filedes, Node **all_messages, int n);

void inject_script_into_html(message *msg);

void modify_accept_encoding(message *curr_message);

void insert_buffer_into_message(message *msg, char *buffer, int buffer_length);

void update_message_header_no_chunk(message *msg);