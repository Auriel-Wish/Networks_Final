#include "table.h"

typedef struct {
    HashTable_T *table;
    unsigned size;
    unsigned capacity;
} Cache_T;

typedef struct {
    Buffer_T *buf;
    unsigned long age;
} Cache_Response_T;


Cache_T *create_cache(unsigned capacity);

void free_cache(Cache_T **cache);

bool find_response_in_cache(Cache_T *cache, char *key);

bool is_entry_stale(Cache_T *cache, char *key);

void put_response_in_cache(Cache_T *cache, char *key, Buffer_T *buf, 
    unsigned long insert_time, unsigned long max_age);

void update_response_in_cache(Cache_T *cache, char *key, Buffer_T *buf, 
    unsigned long insert_time, unsigned long max_age);

Cache_Response_T *get_response_from_cache(Cache_T *cache, char *key);