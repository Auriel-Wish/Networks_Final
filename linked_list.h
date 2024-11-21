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
    // bool response_complete;
    // int response_content_length;
    // int response_header_length;
    // int response_total_size;

    int client_fd;
    int server_fd;
    SSL *client_ssl;
    SSL *server_ssl;
} Context_T;

// typedef struct {
//     int filedes;

//     char msg_type;
//     int header_length;
//     int content_length;
//     int total_msg_size;

//     unsigned char *msg_data;
//     bool msg_complete;
// } message;

void append(Node **head, void *data);
void removeNode(Node **head, void *data);
void freeList(Node *head);

Context_T *get_ssl_context_by_client_fd(Node *head, int client_fd);
Context_T *get_ssl_context_by_server_fd(Node *head, int server_fd);