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
    char req_type;
    int request_data_size;

    int filedes;
    char *request_string;
    bool request_complete;
} client_request;

typedef struct {
    int filedes;
    
    int header_size;
    int response_content_length;
    
    char *response_string;
    bool response_complete;
} server_response;

void append(Node **head, void *data);
void removeNode(Node **head, void *data);
void freeList(Node *head);

Context_T *get_ssl_context(Node *head, int filedes);

client_request *get_client_request(Node *head, int filedes);
server_response *get_server_response(Node *head, int filedes);