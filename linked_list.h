#include <openssl/ssl.h>

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

void append(Node **head, void *data);
void removeNode(Node **head, void *data);
void printList(Node *head);
void freeList(Node *head);
Context_T *get_ssl_context(Node *head, int filedes);