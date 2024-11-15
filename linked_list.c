#include "linked_list.h"
#include <stdio.h>
#include <stdlib.h>
// #include <openssl/ssl.h>
#include <openssl/err.h>

Node *createNode(void *data) {
    Node* newNode = (Node*)malloc(sizeof(Node));
    if (newNode == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    newNode->data = data;
    newNode->next = NULL;
    return newNode;
}

void append(Node **head, void *data) {
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
            free(current);
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

Context_T *get_ssl_context(Node *head, int filedes) {
    for (Node *curr = head; curr != NULL; curr = curr->next) {
        Context_T *curr_context = curr->data;
        if (curr_context->filedes == filedes) {
            return curr_context;
        }
    }
    return NULL;
}