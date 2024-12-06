// #include "linked_list.h"
#include "cache.h"
#include "processing.h"

#define BUFFER_SIZE 65536 //64KB

#define CLIENT_FD 0
#define SERVER_FD 1
#define NO_FD_ASSOCIATION 2

// Parser states
// enum {
//     CHUNK_SIZE,
//     CHUNK_SIZE_LF,
//     CHUNK_DATA,
//     CHUNK_DATA_CR,
//     CHUNK_DATA_LF,
//     CHUNK_DONE
// };

bool read_client_request(int client_fd, Node **ssl_contexts, fd_set *active_read_fd_set, int *max_fd, Cache_T *cache, Node **all_messages, int LLM_sockfd, struct sockaddr_un python_addr);

int client_or_server_fd(Node *ssl_contexts, int fd);

bool handle_connect_request(int fd, Node **ssl_contexts, fd_set *active_read_fd_set, int *max_fd);

void set_max_fd(int new_fd, int *max_fd);

bool read_server_response(int server_fd, Node **ssl_contexts, Node **all_messages);

void open_new_conn_to_server(char *hostname, int port, Context_T **curr_context);






