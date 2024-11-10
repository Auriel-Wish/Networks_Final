#include <stdio.h>
#include <stdlib.h>

// Define the structure for a single node in the list
typedef struct Node {
    void *data;          // Pointer to data (can point to any type of data)
    struct Node *next;   // Pointer to the next node
} Node;

void append(Node **head, void *data);
void removeNode(Node **head, void *data);
void printList(Node *head);
void freeList(Node *head);