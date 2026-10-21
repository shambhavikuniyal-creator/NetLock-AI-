#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 100

typedef struct Node {
    char ip_address[16];
    int threat_score;
    struct Node* next;
} Node;

typedef struct {
    Node* buckets[TABLE_SIZE];
} HashTable;

// Helper: DJB2 Hash Function
unsigned int hash(const char* ip) {
    unsigned long hash = 5381;
    int c;
    while ((c = *ip++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % TABLE_SIZE;
}

// Exportable C API Functions
HashTable* create_hash_table() {
    HashTable* table = (HashTable*)malloc(sizeof(HashTable));
    for (int i = 0; i < TABLE_SIZE; i++) {
        table->buckets[i] = NULL;
    }
    return table;
}

void insert_ip(HashTable* table, const char* ip, int score) {
    unsigned int index = hash(ip);
    Node* new_node = (Node*)malloc(sizeof(Node));
    strcpy(new_node->ip_address, ip);
    new_node->threat_score = score;
    new_node->next = table->buckets[index];
    table->buckets[index] = new_node;
    printf("[C-Engine] IP %s blocked in bucket [%d] with threat score: %d%%\n", ip, index, score);
}

int is_ip_blocked(HashTable* table, const char* ip) {
    unsigned int index = hash(ip);
    Node* current = table->buckets[index];
    while (current != NULL) {
        if (strcmp(current->ip_address, ip) == 0) {
            return 1; 
        }
        current = current->next;
    }
    return 0; 
}