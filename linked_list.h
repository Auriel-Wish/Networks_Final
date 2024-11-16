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
    int filedes;
    SSL *ssl;
    char *hostname;
    int port;
} Context_T;

typedef struct {
    int filedes;
    char req_type;
    uint32_t request_data_size;
    bool request_complete;
    char *request_string;
} client_request;

typedef struct {
    int filedes;
    uint32_t response_data_size;
    bool response_complete;
    char *response_string;
} server_response;

void append(Node **head, void *data);
void removeNode(Node **head, void *data);
void printList(Node *head);
void freeList(Node *head);
Context_T *get_ssl_context(Node *head, int filedes);
client_request *get_client_request(Node *head, int filedes);
server_response *get_server_response(Node *head, int filedes);