#ifndef PROCESSING_H
#define PROCESSING_H

#include "linked_list.h"

void generate_certificates(const char *hostname);

char *convert_normal_to_chunked_encoding(char *buffer, int buffer_length, 
    incomplete_message *msg, int *chunked_data_length);

// char *convert_to_chunked_encoding(char *buffer, int buffer_length, 
//     incomplete_message *msg, int *chunked_data_length);

bool contains_chunk_end(char *buffer, int buffer_length);


incomplete_message *modify_header_data(incomplete_message **msg, char *buffer, 
    int filedes, Node **all_messages);

void modify_content_type(incomplete_message *msg);

void modify_accept_encoding(incomplete_message *curr_message);

char *inject_script_into_chunked_html(char *buffer, int *buffer_length);

char* process_chunked_data(incomplete_message *msg, char *buffer, int buffer_size, int *output_buffer_size);

char *add_end_of_message_chunk(char *buffer, int *buffer_length);

char *make_chunk_header_and_end(char *buffer_only_data, int *data_length);

char *get_content_length_ptr(char *str);

void print_buffer(unsigned char *m, unsigned size);

void print_buffer_s(char *m, unsigned size);

bool is_request(char *buffer);

#endif

