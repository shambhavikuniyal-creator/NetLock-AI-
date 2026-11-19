#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 10007

typedef struct Node {
    char ip[16];
    struct Node* next;
} Node;

Node* hashTable[TABLE_SIZE];

unsigned int djb2_hash(const char* str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % TABLE_SIZE;
}

void insert_ip(const char* ip) {
    unsigned int index = djb2_hash(ip);
    Node* current = hashTable[index];
    while (current != NULL) {
        if (strcmp(current->ip, ip) == 0) return;
        current = current->next;
    }
    Node* newNode = (Node*)malloc(sizeof(Node));
    strncpy(newNode->ip, ip, 16);
    newNode->next = hashTable[index];
    hashTable[index] = newNode;
}

int check_ip(const char* ip) {
    unsigned int index = djb2_hash(ip);
    Node* current = hashTable[index];
    while (current != NULL) {
        if (strcmp(current->ip, ip) == 0) return 1; // Blocked
        current = current->next;
    }
    return 0; // Allowed
}

// Function to clear all blocked IPs on startup
void clear_table() {
    for (int i = 0; i < TABLE_SIZE; i++) {
        Node* current = hashTable[i];
        while (current != NULL) {
            Node* temp = current;
            current = current->next;
            free(temp);
        }
        hashTable[i] = NULL;
    }
}