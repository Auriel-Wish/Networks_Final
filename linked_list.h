#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <openssl/ssl.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/un.h>

// Define the structure for a single node in the list
typedef struct Node {
    void *data;          // Pointer to data (can point to any type of data)
    struct Node *next;   // Pointer to the next node
} Node;

typedef struct {
    int client_fd;
    int server_fd;
    SSL *client_ssl;
    SSL *server_ssl;
    char *hostname;
} Context_T;

typedef struct {
    int filedes;
    int content_length;
    int content_length_read;
    bool header_complete;
    enum {
        NORMAL_ENCODING,
        CHUNKED_ENCODING,
        OTHER_ENCODING
    } original_content_type;
    enum {
        END_OF_HEADER,
        END_OF_CHUNK
    } rn_state;
    enum {
        CLIENT_MSG,
        SERVER_MSG,
        OTHER_MSG
    } source;
    char *header;
    int original_header_length;
    bool header_sent;
    bool read_ended_with_slash_r;
} incomplete_message;

void append(Node **head, void *data);
void removeNode(Node **head, void *data);
void freeList(Node *head);

Context_T *get_ssl_context_by_client_fd(Node *head, int client_fd);
Context_T *get_ssl_context_by_server_fd(Node *head, int server_fd);
// message *get_message_by_filedes(Node *head, int filedes);
incomplete_message *get_incomplete_message_by_filedes(Node *head, int filedes);
void modify_content_type(incomplete_message *msg);

#endif

// typedef struct {
//     int filedes;

//     // char msg_type;
//     int header_length;
//     int content_length;
//     int bytes_of_content_read;

//     char *header;
//     unsigned char *content;

//     bool header_complete;
//     bool msg_complete;

//     int content_type;

//     // Chunked encoding processing state
//     int chunk_state;
//     int chunk_size;
//     int bytes_read_in_chunk;
//     char chunk_size_str[16];
//     int chunk_size_str_index;
// } message;