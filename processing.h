#include "linked_list.h"

void generate_certificates(const char *hostname);

char *convert_to_chunked_encoding(char *buffer, int buffer_length, 
    incomplete_message *msg, int *chunked_data_length);

bool contains_chunk_end(char *buffer, int buffer_length);

incomplete_message *modify_header_data(incomplete_message **msg, char *buffer, 
    int filedes, Node **all_messages);

void modify_content_type(incomplete_message *msg);

void modify_accept_encoding(incomplete_message *curr_message);

char *inject_script_into_chunked_html(char *buffer, int *buffer_length);

char *get_content_length_ptr(char *str);

void print_buffer(unsigned char *m, unsigned size);

