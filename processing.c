#include "processing.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <zlib.h>

void generate_certificates(const char *hostname) {
    char command[1024];

    // Generate a private key for the hostname
    snprintf(command, sizeof(command), "openssl genpkey -algorithm RSA -out %s.key -pkeyopt rsa_keygen_bits:2048 > /dev/null 2>&1", hostname);
    system(command);

    // Create a temporary OpenSSL configuration file to specify SAN, Key Usage, and EKU for the CSR
    snprintf(command, sizeof(command), 
        "echo \"[ req ]\n"
        "default_bits = 2048\n"
        "distinguished_name = req_distinguished_name\n"
        "req_extensions = v3_req\n"
        "[ req_distinguished_name ]\n"
        "[ v3_req ]\n"
        "subjectAltName = @alt_names\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "[ alt_names ]\n"
        "DNS.1 = %s\" > %s.cnf", 
        hostname, hostname);
    system(command);

    // Generate a CSR using the private key and include SAN, Key Usage, and EKU from the configuration
    snprintf(command, sizeof(command), "openssl req -new -key %s.key -out %s.csr -subj \"/CN=%s\" -config %s.cnf > /dev/null 2>&1", hostname, hostname, hostname, hostname);
    system(command);

    // Generate the certificate signed by the CA (using Networks_Final_Project.key and Networks_Final_Project.crt)
    snprintf(command, sizeof(command), "openssl x509 -req -in %s.csr -CA Networks_Final_Project.crt -CAkey Networks_Final_Project.key -CAcreateserial -out %s.crt -days 365 -sha256 -extfile %s.cnf -extensions v3_req > /dev/null 2>&1", hostname, hostname, hostname);
    system(command);

    // Clean up CSR and temporary configuration file after signing
    snprintf(command, sizeof(command), "rm %s.csr %s.cnf > /dev/null 2>&1", hostname, hostname);
    system(command);
}

char *convert_normal_to_chunked_encoding(char *buffer, int buffer_length, incomplete_message *msg, int *chunked_data_length) {
    if (buffer == NULL || buffer_length <= 0 || msg == NULL) {
        return NULL;
    }

    // Calculate the maximum size of the output, considering chunk size metadata
    // Each chunk has: <chunk size in hex>\r\n<data>\r\n
    // Plus space for the final "0\r\n\r\n" and null terminator if necessary
    int max_output_size = buffer_length + (buffer_length / 16 + 1) * 10 + 10;
    char *chunked = malloc(max_output_size);
    if (!chunked) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    char *output_ptr = chunked; // Pointer for writing into the output buffer
    int remaining = buffer_length; // Remaining bytes in the input buffer
    char *input_ptr = buffer; // Pointer for reading from the input buffer

    while (remaining > 0) {
        // Calculate the size of the current chunk
        int chunk_size = remaining;

        // Write the chunk size in hexadecimal, followed by \r\n
        // int header_length = sprintf(output_ptr, "%x\r\n", chunk_size);
        int header_length = snprintf(output_ptr, max_output_size, "%x\r\n", chunk_size);

        output_ptr += header_length;

        // Copy the chunk data into the output buffer
        memcpy(output_ptr, input_ptr, chunk_size);
        output_ptr += chunk_size;

        // Add \r\n after the chunk data
        memcpy(output_ptr, "\r\n", 2);
        output_ptr += 2;

        // Update the pointers and decrement the remaining data
        input_ptr += chunk_size;
        remaining -= chunk_size;
    }

    // If all content has been read, append the final chunk terminator
    if (msg->content_length_read >= msg->content_length) {
        memcpy(output_ptr, "0\r\n\r\n", 5);
        output_ptr += 5;
    }

    // Calculate the length of the chunked data
    *chunked_data_length = output_ptr - chunked;

    // Null-terminate the output buffer
    *output_ptr = '\0';

    return chunked;
}

bool contains_chunk_end(char *buffer, int buffer_length) {
    for (int i = 0; i < buffer_length - 4; i++) {
        if (buffer[i] == '0' && buffer[i + 1] == '\r' && buffer[i + 2] == '\n' && buffer[i + 3] == '\r' && buffer[i + 4] == '\n') {
            return true;
        }
    }
    return false;
}

incomplete_message *modify_header_data(incomplete_message **msg, char *buffer, int filedes, Node **all_messages) {
    incomplete_message *curr_message = *msg;
    if (curr_message == NULL) {
        curr_message = malloc(sizeof(incomplete_message));
        assert(curr_message != NULL);
        curr_message->filedes = filedes;
        curr_message->content_length = -1;
        curr_message->content_length_read = 0;
        curr_message->header_complete = false;
        curr_message->header = NULL;
        curr_message->original_header_length = 0;
        curr_message->header_sent = false;
        curr_message->original_content_type = OTHER_ENCODING;
        curr_message->rn_state = END_OF_CHUNK;
        curr_message->read_ended_with_slash_r = false;
        curr_message->accept_encoding_modified = false;
        curr_message->content_type_modified = false;
        append(all_messages, curr_message);
    }

    char *header_end = strstr(buffer, "\r\n\r\n");
    char *only_header = NULL;
    if (header_end != NULL) {
        curr_message->header_complete = true;
        int only_header_size = header_end - buffer + 4;
        only_header = malloc(only_header_size + 1);
        memcpy(only_header, buffer, only_header_size);
        only_header[only_header_size] = '\0';
    }
    else {
        only_header = malloc(strlen(buffer) + 1);
        strcpy(only_header, buffer);
        only_header[strlen(buffer)] = '\0';
    }

    curr_message->original_header_length += strlen(only_header);
    if (curr_message->header == NULL) {
        curr_message->header = malloc(curr_message->original_header_length + 1);
        assert(curr_message->header != NULL);
        strcpy(curr_message->header, only_header);
    } else {
        curr_message->header = realloc(curr_message->header, strlen(curr_message->header) + strlen(only_header) + 1);
        assert(curr_message->header != NULL);
        strcat(curr_message->header, only_header);
    }

    if (curr_message->content_length == -1) {
        curr_message->content_length = get_content_length(curr_message->header);
    }
    if (curr_message->original_content_type == OTHER_ENCODING) {
        curr_message->original_content_type = get_content_type(curr_message->header);
    }

    bool msg_is_request = is_request(curr_message->header);

    if (msg_is_request && !(curr_message->accept_encoding_modified)) {
        modify_accept_encoding(curr_message);
    }
    if (!msg_is_request && !(curr_message->content_type_modified)) {
        modify_content_type(curr_message);
    }

    return curr_message;
}

int get_content_type(char *header) {
    const char *content_type_str = "Content-Length:";
    char *content_type_start = strcasestr(header, content_type_str);
    if (content_type_start != NULL) {
        return NORMAL_ENCODING;
    }

    const char *transfer_encoding_str = "Transfer-Encoding: chunked";
    char *transfer_encoding_start = strcasestr(header, transfer_encoding_str);
    if (transfer_encoding_start != NULL) {
        return CHUNKED_ENCODING;
    }

    return OTHER_ENCODING;
}

bool is_quora(char *hostname) {
    return (strcmp(hostname, "www.quora.com") == 0);
    // return (strcmp(hostname, "www.quora.com") == 0) || (strcmp(hostname, "www.reddit.com") == 0 || (strcmp(hostname, "reddit.com") == 0));
    // return (strcmp(hostname, "www.quora.com") == 0) || (strcmp(hostname, "wikipedia.org") == 0 || (strcmp(hostname, "en.wikipedia.org") == 0));
}

int get_content_length(char *header) {
    const char *content_length_str = "Content-Length:";
    char *content_length_start = strcasestr(header, content_length_str);

    if (content_length_start) {
        // Extract the content length value
        char *content_length_value = content_length_start + strlen(content_length_str);
        while (*content_length_value == ' ') {
            content_length_value++;
        }
        return atoi(content_length_value);
    }

    return -1;
}

void modify_content_type(incomplete_message *msg) {
    if (msg == NULL || msg->header == NULL) {
        return; // Gracefully handle null inputs
    }

    const char *content_length_str = "Content-Length:";
    const char *transfer_encoding_str = "Transfer-Encoding: chunked\r\n";

    char *header = msg->header;
    char *content_length_start = strcasestr(header, content_length_str); // Case-insensitive search for Content-Length

    // Remove the Content-Length header if it exists
    if (content_length_start) {
        char *line_end = strstr(content_length_start, "\r\n");
        if (line_end) {
            // Calculate the length of the line to remove
            memmove(content_length_start, line_end + 2, strlen(line_end + 2) + 1); // Shift remaining data
        } else {
            // Handle case where Content-Length is the last line in the header
            *content_length_start = '\0';
        }
    }

    // Check if "Transfer-Encoding: chunked" already exists
    char *transfer_encoding_start = strcasestr(header, "Transfer-Encoding:");

    if (transfer_encoding_start == NULL) {
        // Add "Transfer-Encoding: chunked" if it doesn't exist
        size_t chunked_line_length = strlen(transfer_encoding_str);

        // Find the first \r\n after the status line
        char *first_crlf = strstr(header, "\r\n");
        if (first_crlf) {
            size_t status_line_length = first_crlf - header + 2; // +2 includes \r\n
            size_t original_header_length = msg->original_header_length;
            size_t new_header_length = original_header_length + chunked_line_length;

            // Allocate memory for the new header
            char *new_header = malloc(new_header_length + 1); // +1 for null terminator
            if (!new_header) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }

            // Build the new header
            strncpy(new_header, header, status_line_length); // Copy the status line
            new_header[status_line_length] = '\0'; // Null-terminate temporarily
            strcat(new_header, transfer_encoding_str); // Append "Transfer-Encoding: chunked"
            strcat(new_header, first_crlf + 2); // Append the rest of the original header

            // Replace old header with new header
            free(msg->header);
            msg->header = new_header;
            msg->content_type_modified = true;
        }
    }
}

void modify_accept_encoding(incomplete_message *msg) {
    if (msg == NULL || msg->header == NULL) {
        return; // Handle null inputs gracefully
    }

    // Define the "Accept-Encoding: Identity" string
    const char *new_accept_encoding = "Accept-Encoding: Identity\r\n";

    // Look for the Accept-Encoding header in the existing header
    char *header = msg->header;
    char *accept_encoding_pos = strstr(header, "Accept-Encoding:");
    
    if (accept_encoding_pos != NULL) {
        // Find the end of the Accept-Encoding header line
        char *end_of_line = strstr(accept_encoding_pos, "\r\n");
        if (end_of_line != NULL) {
            // Remove the existing Accept-Encoding header
            memmove(accept_encoding_pos, end_of_line + 2, strlen(end_of_line + 2) + 1);
        }
    }

    // Find the first occurrence of \r\n
    char *first_rn = strstr(header, "\r\n");
    if (first_rn != NULL) {
        // Insert the new Accept-Encoding: Identity header after the first \r\n
        size_t new_header_length = msg->original_header_length + strlen(new_accept_encoding);
        char *new_header = malloc(new_header_length + 1); // +1 for the null terminator
        if (new_header == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            return; // Handle memory allocation failure gracefully
        }

        // Copy the part before the first \r\n
        size_t prefix_length = first_rn - header + 2; // Include the \r\n
        strncpy(new_header, header, prefix_length);
        new_header[prefix_length] = '\0';

        // Append the new Accept-Encoding header
        strcat(new_header, new_accept_encoding);

        // Append the rest of the original header
        strcat(new_header, first_rn + 2);

        // Update the incomplete_message fields
        free(msg->header);
        msg->header = new_header;
        msg->accept_encoding_modified = true;
    }
}

char *inject_script_into_chunked_html(char *buffer, int *buffer_length) {
    const char *body_tag = "</body>";

    if (strstr(buffer, body_tag) == NULL) {
        return buffer;
    }

    size_t buffer_len = *buffer_length;
    char *ptr = buffer;
    char *buffer_end = buffer + buffer_len;

    while (ptr < buffer_end) {
        // Parse chunk size
        char *chunk_size_start = ptr;
        char *chunk_size_end = strstr(ptr, "\r\n");
        if (!chunk_size_end || chunk_size_end >= buffer_end) {
            // Invalid chunked data
            return buffer;
        }

        size_t chunk_size_len = chunk_size_end - chunk_size_start;
        if (chunk_size_len >= 16) {
            // Chunk size too big
            return buffer;
        }

        char chunk_size_str[17];
        memcpy(chunk_size_str, chunk_size_start, chunk_size_len);
        chunk_size_str[chunk_size_len] = '\0';

        // Parse chunk size
        unsigned long chunk_size = strtoul(chunk_size_str, NULL, 16);

        if (chunk_size == 0) {
            // Last chunk (size zero), stop parsing
            break;
        }

        // Move ptr to chunk data
        char *chunk_data_start = chunk_size_end + 2; // Skip \r\n

        if (chunk_data_start + chunk_size + 2 > buffer_end) {
            // Invalid data
            return buffer;
        }

        char *chunk_data_end = chunk_data_start + chunk_size;

        if (chunk_data_end[0] != '\r' || chunk_data_end[1] != '\n') {
            // Invalid chunk ending
            return buffer;
        }

        // Search for </body> in chunk data
        char *body_tag_pos = memmem(chunk_data_start, chunk_size, body_tag, strlen(body_tag));

        if (body_tag_pos != NULL) {
            // Found </body> in this chunk

            // We need to inject the script before </body>

            // Compute positions and lengths
            size_t script_len = strlen(SCRIPT_TO_INJECT);

            size_t data_before_body_tag_len = body_tag_pos - chunk_data_start;
            size_t data_after_body_tag_len = chunk_data_end - body_tag_pos;

            // New chunk size
            size_t new_chunk_size = chunk_size + script_len;

            // Need to adjust the chunk size field

            // Calculate the new chunk size string length
            char new_chunk_size_str[17];
            int new_chunk_size_str_len = snprintf(new_chunk_size_str, 17, "%lx", new_chunk_size);

            // Calculate difference in chunk size field length
            int old_chunk_size_str_len = chunk_size_len;

            int size_diff = (new_chunk_size_str_len - old_chunk_size_str_len) + script_len;

            // Compute new buffer length
            size_t prefix_len = chunk_size_start - buffer;
            size_t suffix_len = buffer_end - (chunk_data_end + 2);

            size_t new_buffer_length = buffer_len + size_diff;

            // Allocate new buffer
            char *new_buffer = malloc(new_buffer_length);
            if (!new_buffer) {
                return buffer;
            }

            // Copy prefix (before chunk size)
            memcpy(new_buffer, buffer, prefix_len);

            // Write new chunk size
            memcpy(new_buffer + prefix_len, new_chunk_size_str, new_chunk_size_str_len);

            // Write \r\n
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len, "\r\n", 2);

            // Copy data before </body>
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2, chunk_data_start, data_before_body_tag_len);

            // Copy script
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + data_before_body_tag_len, SCRIPT_TO_INJECT, script_len);

            // Copy data after </body> (includes </body> and trailing \r\n)
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + data_before_body_tag_len + script_len,
                   body_tag_pos, data_after_body_tag_len + 2);

            // Copy suffix
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + new_chunk_size + 2,
                   chunk_data_end + 2, suffix_len);

            // Update buffer_length
            *buffer_length = new_buffer_length;

            // Return new buffer
            return new_buffer;
        }

        // Move to next chunk
        ptr = chunk_data_end + 2; // Move past \r\n
    }

    // </body> not found
    return buffer;
}

bool is_request(char *buffer) {
    if (buffer == NULL) {
        return false;
    }

    // List of valid HTTP methods
    const char *methods[] = {
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
    };

    // Iterate through all valid methods and check if the buffer contains one of them
    size_t num_methods = sizeof(methods) / sizeof(methods[0]);
    for (size_t i = 0; i < num_methods; i++) {
        if (strncmp(buffer, methods[i], strlen(methods[i])) == 0) { // Check if buffer starts with the method
            return true;
        }
    }

    return false;
}

bool request_might_have_data(const char *buffer) {
    if (buffer == NULL) {
        return false;
    }

    // List of HTTP methods that generally have a body
    const char *methods_with_data[] = {
        "POST", "PUT", "PATCH"
    };

    // Iterate through methods that may have a body
    size_t num_methods = sizeof(methods_with_data) / sizeof(methods_with_data[0]);
    for (size_t i = 0; i < num_methods; i++) {
        if (strstr(buffer, methods_with_data[i]) != NULL) { // Check if method is in the buffer
            return true;
        }
    }

    return false;
}

char *make_chunk_header_and_end(char *buffer_only_data, int *data_length) {
    char chunk_header[20];
    snprintf(chunk_header, 20, "%X\r\n", *data_length);

    // Allocate memory for header, data, \r\n, and null terminator
    size_t chunk_header_len = strlen(chunk_header);
    size_t total_size = chunk_header_len + *data_length + 2 + 1; // 2 for \r\n, 1 for \0
    char *chunked_data = malloc(total_size);

    if (!chunked_data) {
        free(buffer_only_data);
        return NULL; // Handle allocation failure
    }

    // Copy header, data, and append \r\n
    strcpy(chunked_data, chunk_header);
    memcpy(chunked_data + chunk_header_len, buffer_only_data, *data_length);

    chunked_data[chunk_header_len + *data_length] = '\r';
    chunked_data[chunk_header_len + *data_length + 1] = '\n';
    chunked_data[chunk_header_len + *data_length + 2] = '\0';

    // Update data length to include header and \r\n
    *data_length = chunk_header_len + *data_length + 2;

    free(buffer_only_data); // Free input buffer

    return chunked_data;
}

char *add_end_of_message_chunk(char *buffer, int *buffer_length) {
    char *end_chunk = "0\r\n\r\n";
    int end_chunk_length = strlen(end_chunk);
    char *new_buffer = malloc(*buffer_length + end_chunk_length + 1);
    memcpy(new_buffer, buffer, *buffer_length);
    memcpy(new_buffer + *buffer_length, end_chunk, end_chunk_length + 1); // +1 to include the null terminator
    *buffer_length += end_chunk_length;
    free(buffer);
    return new_buffer;
}

char *find_next_rn(char *buffer, int buffer_size) {
    char *rn_ptr = NULL;
    for (char *search_ptr = buffer; search_ptr < buffer + buffer_size - 1; search_ptr++) {
        if (search_ptr[0] == '\r' && search_ptr[1] == '\n') {
            rn_ptr = search_ptr;
            break;
        }
    }
    return rn_ptr;
}

char* process_chunked_data(incomplete_message *msg, char *buffer, int buffer_size, int *output_buffer_size) {
    if (msg->read_ended_with_slash_r) {
        if (buffer[0] == '\n') {
            if (buffer_size >= 3 && buffer[1] == '\r' && buffer[2] == '\n') {
                *output_buffer_size = 0;
                char *ret = malloc(5 + 1);
                strcpy(ret, "0\r\n\r\n");
                return ret;
            }
            else {
                memmove(buffer + 1, buffer, buffer_size);
                buffer[0] = '\r';
                buffer_size++;
                msg->read_ended_with_slash_r = false;
            }
        }
    }
    
    char *new_buffer = NULL;
    *output_buffer_size = 0;
    char *rn_ptr = find_next_rn(buffer, buffer_size);
    char *last_rn_ptr = buffer;
    bool done = false;

    while (last_rn_ptr != NULL) {
        if (rn_ptr == NULL) {
            done = true;
            rn_ptr = buffer + buffer_size;
        }

        // if what comes between last_rn_ptr and rn_ptr is a chunk size
        if (msg->rn_state == END_OF_CHUNK) {
            msg->rn_state = END_OF_HEADER;
        }
        // if what comes between last_rn_ptr and rn_ptr is data
        else if (msg->rn_state == END_OF_HEADER) {
            int curr_chunk_size = rn_ptr - last_rn_ptr;

            // place data in new buffer
            if (new_buffer == NULL) {
                new_buffer = malloc(curr_chunk_size);
                memcpy(new_buffer, last_rn_ptr, curr_chunk_size);
            }
            // if new buffer is already allocated, realloc and copy data
            else {
                new_buffer = realloc(new_buffer, *output_buffer_size + curr_chunk_size);
                memcpy(new_buffer + *output_buffer_size, last_rn_ptr, curr_chunk_size);
            }

            *output_buffer_size += curr_chunk_size;

            msg->rn_state = END_OF_CHUNK;
        }

        if (done) {
            // flip state back because the next read will should start from this state even though
            // the function flipped the state
            if (msg->rn_state == END_OF_HEADER) {
                msg->rn_state = END_OF_CHUNK;
            } else if (msg->rn_state == END_OF_CHUNK) {
                msg->rn_state = END_OF_HEADER;
            }

            if (new_buffer != NULL && *output_buffer_size > 0) {
                if (new_buffer[*output_buffer_size - 1] == '\r') {
                    msg->read_ended_with_slash_r = true;
                    *output_buffer_size -= 1;
                }
            }

            break;
        }

        // update pointers
        last_rn_ptr = rn_ptr + 2;
        rn_ptr = find_next_rn(last_rn_ptr, buffer + buffer_size - last_rn_ptr);
    }

    char *to_send = NULL;
    if (new_buffer != NULL) {
        to_send = make_chunk_header_and_end(new_buffer, output_buffer_size);
    }
    
    return to_send;
}