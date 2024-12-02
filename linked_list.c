#include "linked_list.h"
#include <stdio.h>
#include <stdlib.h>
// #include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>

Node *createNode(void *data) {
    Node* newNode = (Node*)malloc(sizeof(Node));
    if (newNode == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    // Why would you create a node with no data?
    assert(data != NULL);
    newNode->data = data;
    newNode->next = NULL;
    return newNode;
}

void append(Node **head, void *data) {
    assert(data != NULL);
    Node *newNode = createNode(data);
    if (*head == NULL) {
        *head = newNode;
        return;
    }

    Node *current = *head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = newNode;
}

void removeNode(Node **head, void *data) {
    Node *current = *head;
    Node *prev = NULL;

    while (current != NULL) {
        if (current->data == data) {
            if (prev == NULL) {
                *head = current->next;
            } else {
                prev->next = current->next;
            }

            free(current->data);
            current->data = NULL;

            free(current);
            current = NULL;

            return;
        }
        prev = current;
        current = current->next;
    }
}

void freeList(Node *head) {
    Node *temp;
    while (head != NULL) {
        temp = head;
        head = head->next;
        free(temp);
    }
}

Context_T *get_ssl_context_by_client_fd(Node *head, int client_fd) {
    for (Node *curr = head; curr != NULL; curr = curr->next) {
        Context_T *curr_context = curr->data;
        if (curr_context->client_fd == client_fd) {
            return curr_context;
        }
    }
    return NULL;
}

Context_T *get_ssl_context_by_server_fd(Node *head, int server_fd) {
    for (Node *curr = head; curr != NULL; curr = curr->next) {
        Context_T *curr_context = curr->data;
        if (curr_context->server_fd == server_fd) {
            return curr_context;
        }
    }
    return NULL;
}

message *get_message_by_filedes(Node *head, int filedes) {
    for (Node *curr = head; curr != NULL; curr = curr->next) {
        message *curr_message = curr->data;
        if (curr_message->filedes == filedes) {
            return curr_message;
        }
    }
    return NULL;
}