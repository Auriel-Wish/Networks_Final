#include "cache.h"
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>

void print_cache(Cache_T *cache)
{
    printf("\nCache size is %d\n", cache->size);
    printf("Cache capacity is %d\n\n", cache->capacity);
}

Cache_T *create_cache(unsigned capacity)
{
    Cache_T *cache = malloc(sizeof(Cache_T));
    cache->table = create_table(capacity);
    cache->size = 0;
    cache->capacity = capacity;

    return cache;
}

void free_cache(Cache_T **cache)
{
    free_table(&(*cache)->table);
    free(*cache);
    *cache = NULL;
}

bool find_response_in_cache(Cache_T *cache, char *key)
{
    Entry_T *entry = get_entry_from_table(cache->table, key);

    if (entry == NULL) {
        return false;
    }

    return true;
}

bool is_entry_stale(Cache_T *cache, char *key)
{
    Entry_T *entry = get_entry_from_table(cache->table, key);
    
    // Do not allow this function to be misused
    assert(entry != NULL);

    time_t current_time = time(NULL);
    unsigned long now = (unsigned long)current_time;

    unsigned long entry_age = now - entry->insert_time;

    if (entry_age >= entry->max_age) {
        return true;
    }

    return false;
}

void put_response_in_cache(Cache_T *cache, char *key, Buffer_T *buf,
    unsigned long insert_time, unsigned long max_age)
{
    // check if cache is at max capacity
    if (cache->size == cache->capacity) {

        printf("The cache is full\n");

        // TODO: cache is full, kick something out
        Entry_T *entry = find_entry_to_delete(cache->table);

        printf("Deleting entry: %s\n", entry->key);

        delete_entry_from_table(cache->table, entry);


        cache->size--;
    }

    time_t current_time = time(NULL);
    unsigned long now = (unsigned long)current_time;
    Entry_T *entry = create_entry(key, buf, max_age, insert_time, now);

    add_entry_to_table(cache->table, entry);
    cache->size++;
}

void update_response_in_cache(Cache_T *cache, char *key, Buffer_T *buf,
    unsigned long insert_time, unsigned long max_age)
{
    time_t current_time = time(NULL);
    unsigned long now = (unsigned long)current_time;

    Entry_T *entry = create_entry(key, buf, insert_time, max_age, now);
    bool outcome = update_entry_in_table(cache->table, entry);

    assert(outcome);
}

Cache_Response_T *get_response_from_cache(Cache_T *cache, char *key)
{
    Cache_Response_T *resp = malloc(sizeof(Cache_Response_T));

    Entry_T *entry = get_entry_from_table(cache->table, key);

    time_t current_time = time(NULL);
    unsigned long now = (unsigned long)current_time;

    unsigned long age = now - entry->insert_time;

    entry->access_time = now;

    resp->age = age;
    resp->buf = entry->response;
    return resp;
}