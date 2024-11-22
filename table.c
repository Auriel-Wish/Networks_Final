#include "table.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>


/* Making the table twice as large as it strictly needs to be to minimize
 * collisions */
unsigned BUCKET_MULTIPLIER = 2;

/* This function implements the DJB2 hash function created by Dan Berstein */
unsigned long compute_index(unsigned char *str, unsigned long table_size)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++) != 0)
        hash = ((hash << 5) + hash) + c;

    /* Modding by table size to make sure the resulting index is within the
     * bounds of the table */
    return hash % table_size;
}

Buffer_T *new_Buffer_T(char *buf, int size)
{
    Buffer_T *buffer = malloc(sizeof(Buffer_T));
    buffer->buf = buf;
    buffer->size = size;

    return buffer;
}

void free_Buffer_T(Buffer_T **buffer)
{
    free((*buffer)->buf);
    (*buffer)->buf = NULL;

    free(*buffer);
    *buffer = NULL;
}

Entry_T *create_entry(char *key, Buffer_T *response, unsigned long max_age, 
    unsigned long insert_time, unsigned long access_time)
{
    Entry_T *entry = malloc(sizeof(Entry_T));
    assert(entry != NULL);

    entry->key = key;
    entry->response = response;
    entry->max_age = max_age;
    entry->insert_time = insert_time;
    entry->access_time = access_time;

    return entry;
}

void free_entry(Entry_T **entry)
{
    // printf("\nFREEING ENTRY WITH FILE NAME %s\n\n", (*entry)->filename);
    if (entry != NULL && *entry != NULL)
    {
        free((*entry)->key);
        free_Buffer_T(&(*entry)->response);
        free(*entry);
        *entry = NULL;
    }
}

HashTable_T *create_table(unsigned capacity)
{
    HashTable_T *table = malloc(sizeof(HashTable_T));
    assert(table != NULL);

    /* Initializing all memory to NULL to make sure that we can differentiate
     * between initialized and uninitialized entries */
    table->entries = calloc(BUCKET_MULTIPLIER * capacity, sizeof(Entry_T *));
    assert(table->entries != NULL);

    table->buckets = BUCKET_MULTIPLIER * capacity;
    table->size = 0;
    return table;
}

void free_table(HashTable_T **table)
{
    if (table != NULL && *table != NULL)
    {
        for (unsigned i = 0; i < (*table)->buckets; i++)
        {
            // If there is an entry at that bucket, free it.
            if ((*table)->entries[i] != NULL)
            {
                free_entry(&(*table)->entries[i]);
            }
        }

        free((*table)->entries);
        (*table)->entries = NULL;

        free(*table);
        *table = NULL;
    }
}

bool add_entry_to_table(HashTable_T *table, Entry_T *new_entry)
{
    //need the key

    // this is a bandaid
    unsigned long index = compute_index((unsigned char *)new_entry->key, table->buckets);

    /* If there is already an entry in the target insertion slot:
     * 1. Check to see if it is the same file (and if so, update it)
     * 2. If it isn't, use linear probing to find the next open bucket */

    unsigned i = 0;

    Entry_T **target = &table->entries[index];

    /* If the target insertion slot has an entry*/
    while (*target != NULL)
    {

        /* Check if the filename in the table is the same as the one being
         * inserted */
        if (strcmp((*target)->key, new_entry->key) == 0)
        {
            // If it is the same file, replace the old entry with the new
            free_entry(target);
            *target = new_entry;
            return true;
        }

        // Otherwise, keep linear probing
        i++;
        target = &table->entries[(index + i) % table->buckets];

        // Major issue
        if (i >= table->buckets)
        {
            assert(false);
        }
    }

    // Debug print
    // printf("\nPROBING INSERTION: i ended up being %d\n\n", i);

    /* If the target insertion slot has no entry, go ahead and insert */

    //idk what's going on here
    *target = new_entry;
    return false;
}


// helper function
Entry_T **find_entry_address_in_table(HashTable_T *table, char *key)
{
    unsigned long index = compute_index((unsigned char *) key, table->buckets);
    unsigned i = 0;
    Entry_T **address = &table->entries[index];

    // If the file we are looking for doesn't exist in the table
    if (address == NULL)
    {
        return NULL;
    }
    if (*address == NULL)
    {
        return NULL;
    }

    // If filenames match immediately, we're already at the right index
    bool filenames_match = (strcmp((*address)->key,
                                   key) == 0);

    while (!filenames_match)
    {
        i++;
        address = &table->entries[(index + i) % table->buckets];

        /* If we run out of existing entries to probe, the file isn't in the
         * table */
        if (address == NULL)
        {
            return NULL;
        }
        if (*address == NULL)
        {
            return NULL;
        }

        // i should never get this big. We have a major problem
        if (i >= table->buckets)
        {
            assert(false);
        }

        filenames_match = (strcmp((*address)->key,
                                  key) == 0);
    }

    // Debug print
    // printf("\nPROBING RETRIEVAL: i ended up being %d\n\n", i);
    return address;
}

Entry_T *get_entry_from_table(HashTable_T *table, char *key)
{
    Entry_T **address = find_entry_address_in_table(table, key);
    if (address == NULL)
    {
        // printf("The FILE %s DOES NOT already exist in the table.\n", filename);
        return NULL;
    }

    Entry_T *target = *address;
    return target;
}

bool update_entry_in_table(HashTable_T *table, Entry_T *to_update)
{
    Entry_T **target = find_entry_address_in_table(table, to_update->key);
    assert(target != NULL);

    // free(target);
    // Intentionally leaking memory in the hash table because I'm dense
    *target = to_update;
    
    return true;
}

bool delete_entry_from_table(HashTable_T *table, Entry_T *to_delete)
{
    Entry_T **target = find_entry_address_in_table(table, to_delete->key);
    // If there is no entry to delete
    if (target == NULL)
    {
        return false;
    }

    if (*target == NULL)
    {
        target = NULL;
        return false;
    }

    free_entry(target);
    assert(*target == NULL);

    return true;
}

Entry_T *find_entry_to_delete(HashTable_T *table)
{

    unsigned i = 0;
    unsigned age;
    time_t current_time = time(NULL);
    unsigned long now = (unsigned long)current_time;

    // least recently retrieved
    unsigned long lrr_time = now;
    Entry_T *lrr_entry = NULL;
    Entry_T *backup = NULL;

    // iterate thru the entire table
    while (i < table->buckets) {
        Entry_T **target = &table->entries[i];

        if (*target != NULL ) {
            // find the age of the entry

            printf("Considering deleting entry %s\n", (*target)->key);

            backup = *target;
            age = now - (*target)->insert_time;

            printf("Age of target: %d\n", age);
            printf("Max age of target: %lu\n", (*target)->max_age);
            printf("Last accessed %lu seconds age\n", now - (*target)->access_time);


            // if the entry is stale, return it (to be deleted)
            if (age >= (*target)->max_age) {
                return *target;
            }

            // check and see if this entry is the least recently retrieved
            if ((*target)->access_time < lrr_time) {
                lrr_time = (*target)->access_time;
                lrr_entry = *target;
            }
        }

        i++;
    }

    if (lrr_entry != NULL) {
        return lrr_entry;
    } else {
        // just delete any old thing
        return backup;
    }

    // failed to find something to delete (should never happen)
    assert(false);
}