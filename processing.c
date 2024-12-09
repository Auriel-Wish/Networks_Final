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

    // printf("Generated %s.key and %s.crt signed by Networks_Final_Project with SAN, Key Usage, and EKU.\n", hostname, hostname);
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
        int header_length = sprintf(output_ptr, "%x\r\n", chunk_size);

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
        // printf("\nMAKING NEW MESSAGE\n");
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
        append(all_messages, curr_message);
    }

    else {
        // printf("\nNOT NEW MESSAGE\n");
    }

    if (!(curr_message->header_complete)) {
        char *header_end = strstr(buffer, "\r\n\r\n");
        char *only_header = NULL;
        if (header_end != NULL) {
            curr_message->header_complete = true;
            only_header = malloc(header_end - buffer + 4 + 1);
            memcpy(only_header, buffer, header_end - buffer + 4);
            only_header[header_end - buffer + 4] = '\0';
        }
        else {
            only_header = malloc(strlen(buffer) + 1);
            strcpy(only_header, buffer);
        }

        curr_message->original_header_length += strlen(only_header);
        if (curr_message->header == NULL) {
            curr_message->header = malloc(curr_message->original_header_length + 1);
            assert(curr_message->header != NULL);
            strcpy(curr_message->header, only_header);
        } else {
            curr_message->header = realloc(curr_message->header, curr_message->original_header_length + 1);
            assert(curr_message->header != NULL);
            strcat(curr_message->header, only_header);
        }

        if (is_request(curr_message->header)) {
            modify_accept_encoding(curr_message);
        }
        else {
            modify_content_type(curr_message);
        }
    }

    // printf("Header is:\n %s\n\n", curr_message->header);

    return curr_message;
}

void modify_content_type(incomplete_message *msg) {
    if (msg == NULL || msg->header == NULL) {
        return;
    }

    const char *content_length_str = "Content-Length:";
    const char *transfer_encoding_str = "Transfer-Encoding: chunked";

    char *header = msg->header;
    char *content_length_start = strcasestr(header, content_length_str); // Case-insensitive search for Content-Length

    if (content_length_start) {
        msg->original_content_type = NORMAL_ENCODING;

        // Extract the content length value
        char *content_length_value = content_length_start + strlen(content_length_str);
        while (*content_length_value == ' ') {
            content_length_value++;
        }
        msg->content_length = atoi(content_length_value);

        // Find the end of the Content-Length line
        char *line_end = strstr(content_length_start, "\r\n");
        if (line_end) {
            // Remove the Content-Length line
            // size_t line_length = line_end + 2 - content_length_start;
            memmove(content_length_start, line_end + 2, strlen(line_end + 2) + 1);
        } else {
            // Handle case where Content-Length is the last line
            *content_length_start = '\0';
        }
    }

    // Check if Transfer-Encoding: chunked already exists
    char *transfer_encoding_start = strcasestr(header, transfer_encoding_str);
    if (transfer_encoding_start) {
        msg->original_content_type = CHUNKED_ENCODING;
    }

    if (msg->original_content_type != CHUNKED_ENCODING) {
        // If Transfer-Encoding: chunked is not present, add it
        const char *chunked_line = "\r\nTransfer-Encoding: chunked";
        size_t chunked_line_length = strlen(chunked_line);

        // Find the end of the header
        char *header_end = strstr(header, "\r\n\r\n");
        if (header_end) {
            size_t header_prefix_length = header_end - header;
            size_t new_header_length = header_prefix_length + chunked_line_length + 4; // +4 for \r\n\r\n

            // Allocate memory for the new header
            char *new_header = malloc(new_header_length + 1);
            if (!new_header) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }

            // Build the new header
            strncpy(new_header, header, header_prefix_length); // Copy part before \r\n\r\n
            new_header[header_prefix_length] = '\0'; // Null-terminate temporarily
            strcat(new_header, chunked_line); // Append Transfer-Encoding: chunked
            strcat(new_header, "\r\n\r\n"); // Append \r\n\r\n

            // Replace old header with new header
            free(msg->header);
            msg->header = new_header;
        }
    }
}

void modify_accept_encoding(incomplete_message *curr_message) {
    char *header = curr_message->header;
    size_t header_length = strlen(header);
    size_t i = 0;

    // The new Accept-Encoding line
    const char *new_line = "Accept-Encoding: identity\r\n";
    size_t new_line_length = strlen(new_line);

    while (i < header_length) {
        // Find the end of the current line
        size_t line_start = i;
        while (i < header_length - 1 && !(header[i] == '\r' && header[i + 1] == '\n')) {
            i++;
        }

        if (i >= header_length - 1) {
            // End of header reached or malformed header
            break;
        }

        // Now, header[line_start .. i-1] is the current line (excluding "\r\n")
        size_t line_length = i - line_start;

        // Check if the line contains ':'
        char *colon = memchr(&header[line_start], ':', line_length);
        if (colon) {
            size_t field_name_length = colon - &header[line_start];

            // Remove any trailing whitespace from field name
            while (field_name_length > 0 &&
                   isspace((unsigned char)header[line_start + field_name_length - 1])) {
                field_name_length--;
            }

            // Compare field name to "Accept-Encoding" case-insensitively
            if (field_name_length == strlen("Accept-Encoding") &&
                strncasecmp(&header[line_start], "Accept-Encoding", field_name_length) == 0) {
                // Found the Accept-Encoding header
                size_t old_line_length = (i + 2) - line_start; // Including "\r\n"

                ssize_t diff = (ssize_t)new_line_length - (ssize_t)old_line_length;

                if (diff != 0) {
                    // Shift data to accommodate new line length
                    memmove(&header[line_start + new_line_length],
                            &header[line_start + old_line_length],
                            header_length - (line_start + old_line_length));
                }

                // Copy new line into header
                memcpy(&header[line_start], new_line, new_line_length);

                // Update header length and null-terminate
                header_length += diff;
                header[header_length] = '\0';

                // Header updated; exit the loop
                break;
            }
        }

        // Move past the "\r\n"
        i += 2;
    }
}

char *inject_script_into_chunked_html(char *buffer, int *buffer_length) {
    char *quora_last_line = "addEventListener(\"load\",function(){setTimeout(function(){window.navigator.serviceWorker.register(\"/sw.js\").then(function(t){t.update().catch(function(){})})},100)})";
    const char *body_tag = "</body>";

    if (strstr(buffer, quora_last_line) == NULL || strstr(buffer, body_tag) == NULL) {
        // printf("Didn't find a place to inject\n");
        return buffer;
    }

    printf("Attempting to inject script into chunked HTML\n");


    const char *script_to_inject = 
            "<script>"
            "document.addEventListener('DOMContentLoaded', () => {"
            "  const factCheckButton = document.createElement('button');"
            "  factCheckButton.innerText = 'Run Fact Check';"
            "  factCheckButton.style.position = 'fixed';"
            "  factCheckButton.style.bottom = '10px';"
            "  factCheckButton.style.right = '10px';"
            "  factCheckButton.style.zIndex = '9999';"
            "  factCheckButton.style.padding = '15px';"
            "  factCheckButton.style.backgroundColor = 'white';"
            "  factCheckButton.style.borderRadius = '5px';"
            "  factCheckButton.style.cursor = 'pointer';"
            "  factCheckButton.style.color = 'black';"
            "  factCheckButton.style.border = 'none';"
            "  factCheckButton.style.fontSize = 'large';"
            "  factCheckButton.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';"
            "  factCheckButton.style.transition = 'background-color 0.3s';"
            "  factCheckButton.addEventListener('mouseover', () => {"
            "     factCheckButton.style.backgroundColor = 'gainsboro';"
            "  });"
            "  factCheckButton.addEventListener('mouseout', () => {"
            "     factCheckButton.style.backgroundColor = 'white';"
            "  });"
            "  document.body.appendChild(factCheckButton);"
            ""
            "  const toggleButton = document.createElement('button');"
            "  toggleButton.innerText = '↑';"
            "  toggleButton.style.position = 'fixed';"
            "  toggleButton.style.bottom = '75px';"
            "  toggleButton.style.right = '10px';"
            "  toggleButton.style.zIndex = '9999';"
            "  toggleButton.style.padding = '10px';"
            "  toggleButton.style.backgroundColor = 'white';"
            "  toggleButton.style.borderRadius = '5px';"
            "  toggleButton.style.cursor = 'pointer';"
            "  toggleButton.style.color = 'black';"
            "  toggleButton.style.border = 'none';"
            "  toggleButton.style.fontSize = 'large';"
            "  toggleButton.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';"
            "  toggleButton.style.transition = 'background-color 0.3s';"
            "  toggleButton.addEventListener('mouseover', () => {"
            "     toggleButton.style.backgroundColor = 'gainsboro';"
            "  });"
            "  toggleButton.addEventListener('mouseout', () => {"
            "     toggleButton.style.backgroundColor = 'white';"
            "  });"
            "  document.body.appendChild(toggleButton);"
            ""
            "  let popupDiv = null;" // Store reference to the popupDiv
            "  let is_first = true;"
            ""
            "  factCheckButton.addEventListener('click', async () => {"
            "    const selection = window.getSelection().toString();"
            "    if (selection) {"
            "      if (!popupDiv) {"
            "        popupDiv = document.createElement('div');"
            "        popupDiv.style.position = 'fixed';"
            "        popupDiv.style.top = '10%';"
            "        popupDiv.style.left = '50%';"
            "        popupDiv.style.transform = 'translateX(-50%)';"
            "        popupDiv.style.maxHeight = '50%';"
            "        popupDiv.style.overflowY = 'auto';"
            "        popupDiv.style.padding = '20px';"
            "        popupDiv.style.width = '60%';"
            "        popupDiv.style.backgroundColor = 'white';"
            "        popupDiv.style.color = 'black';"
            "        popupDiv.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';"
            "        popupDiv.style.zIndex = '10000';"
            "        popupDiv.style.borderRadius = '8px';"
            "        popupDiv.style.display = 'none';" // Initially hidden
            "        popupDiv.innerHTML = "
            "          `<div style='display: flex; justify-content: space-between; align-items: center;'>"
            "            <button id='close-button' style='background: none; border: none; font-size: 18px; cursor: pointer; color: black'>&times;</button>"
            "          </div>"
            "          <div id='fact-check-results'></div>`;" // Container for cumulative results
            ""
            "        const closeButton = popupDiv.querySelector('#close-button');"
            "        closeButton.addEventListener('click', () => {"
            "          popupDiv.style.display = 'none';" // Hide the popupDiv
            "        });"
            ""
            "        document.body.appendChild(popupDiv);"
            "      }"
            ""
            "      popupDiv.style.display = 'block';" // Show the popupDiv
            "      const resultsContainer = popupDiv.querySelector('#fact-check-results');"
            ""
            "      const loadingMessage = document.createElement('p');"
            "      loadingMessage.style.fontSize = 'large';"
            "      loadingMessage.innerHTML = '<strong>Fact checking...<br><br></strong>';"
            "      resultsContainer.prepend(loadingMessage);"
            ""
            "      try {"
            "        const response = await fetch('https://www.quora.com/ajax/receive_POST?fact-check-CS112-Final=True', {"
            "          method: 'POST',"
            "          headers: { 'Content-Type': 'application/json' },"
            "          body: JSON.stringify({ text: selection })"
            "        });"
            "        const result = await response.json();"
            "        const factCheckResult = document.createElement('div');"
            "        if (is_first) {factCheckResult.innerHTML = `<p>${result.factCheck}</p>`; is_first = false}"
            "        else {factCheckResult.innerHTML = `<p>${result.factCheck}</p><hr style=\"margin: 30px auto; text-align: center; border: 1px black solid; width: 80%\">`;}"
            "        resultsContainer.prepend(factCheckResult);"
            "        loadingMessage.remove();"
            "      } catch (error) {"
            "        loadingMessage.remove();"
            "        alert('Unable to fact check. Please try again.');"
            "      }"
            "    }"
            "  });"
            ""
            "  toggleButton.addEventListener('click', () => {"
            "    if (popupDiv) {"
            "      popupDiv.style.display = popupDiv.style.display === 'none' ? 'block' : 'none';"
            "    }"
            "  });"
            "});"
            "</script>";

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
            size_t script_len = strlen(script_to_inject);

            size_t data_before_body_tag_len = body_tag_pos - chunk_data_start;
            size_t data_after_body_tag_len = chunk_data_end - body_tag_pos;

            // New chunk size
            size_t new_chunk_size = chunk_size + script_len;

            // Need to adjust the chunk size field

            // Calculate the new chunk size string length
            char new_chunk_size_str[17];
            int new_chunk_size_str_len = sprintf(new_chunk_size_str, "%lx", new_chunk_size);

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
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + data_before_body_tag_len, script_to_inject, script_len);

            // Copy data after </body> (includes </body> and trailing \r\n)
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + data_before_body_tag_len + script_len,
                   body_tag_pos, data_after_body_tag_len + 2);

            // Copy suffix
            memcpy(new_buffer + prefix_len + new_chunk_size_str_len + 2 + new_chunk_size + 2,
                   chunk_data_end + 2, suffix_len);

            // Update buffer_length
            *buffer_length = new_buffer_length;

            printf("Script injected\n");
            // Return new buffer
            return new_buffer;
        }

        // Move to next chunk
        ptr = chunk_data_end + 2; // Move past \r\n
    }

    // </body> not found
    return buffer;
}

char *get_content_length_ptr(char *str) {
    assert(str != NULL);
    char *content_length = strstr(str, "Content-Length: ");
    if (content_length == NULL) {
        content_length = strstr(str, "content-length: ");
    }

    if (content_length == NULL) {
        content_length = strstr(str, "Content-length: ");
    }

    if (content_length == NULL) {
        content_length = strstr(str, "content-Length: ");
    }

    if (content_length == NULL) {
        content_length = strstr(str, "CONTENT-LENGTH: ");
    }

    return content_length;
}

void print_buffer(unsigned char *m, unsigned size)
{
    // printf("Type: %d, Source: %s, Dest: %s, Length: %d, ID: %d\n",
    //        m->h.type, m->h.source, m->h.dest, m->h.length, m->h.message_id);
    // printf("\nSize of buffer: %d\n", size);
    if (size > 0) {
        printf("Message content is: ");
        for (unsigned offset = 0; offset < size; offset++) {
            if (m[offset] == '\0') {
                putchar('.');
            }

            else {
                putchar(m[offset]);
            }
        }

        printf("\n");
    }
}

// char* process_chunked_data(incomplete_message *msg, char *buffer, int *buffer_size, int *output_size) {
//     // Initialize variables
//     char *new_buffer = NULL;
//     int new_buffer_capacity = 0;
//     int new_buffer_length = 0;

//     int pos = 0;          // Current position in the buffer
//     int start = 0;        // Start position for data to be added
//     bool done = false;    // Flag to indicate completion (e.g., encountered 0\r\n\r\n)

//     while (pos < *buffer_size && !done) {
//         // Search for the next occurrence of "\r\n"
//         char *crlf = memchr(buffer + pos, '\r', *buffer_size - pos);
//         if (crlf && (crlf - buffer + 1) < *buffer_size && *(crlf + 1) == '\n') {
//             int crlf_pos = crlf - buffer;
//             int line_length = crlf_pos - pos;

//             if (msg->rn_state == END_OF_CHUNK) {
//                 // Currently expecting a chunk size line
//                 // Extract the chunk size
//                 char chunk_size_str[32];
//                 int copy_length = (line_length < (int)(sizeof(chunk_size_str) - 1)) ? line_length : (int)(sizeof(chunk_size_str) - 1);
//                 memcpy(chunk_size_str, buffer + pos, copy_length);
//                 chunk_size_str[copy_length] = '\0';

//                 // Convert hex string to integer
//                 int chunk_size = (int)strtol(chunk_size_str, NULL, 16);

//                 if (chunk_size == 0) {
//                     // Edge case: 0\r\n\r\n indicates the end of chunks
//                     done = true;
//                 }

//                 // Update state to END_OF_HEADER
//                 msg->rn_state = END_OF_HEADER;

//                 // Move position past "\r\n"
//                 pos = crlf_pos + 2;
//                 start = pos;

//                 // If chunk size is zero, break after processing
//                 if (chunk_size == 0) {
//                     break;
//                 }
//             } else if (msg->rn_state == END_OF_HEADER) {
//                 // Currently expecting chunk data followed by "\r\n"
//                 // Calculate the expected end of chunk data
//                 int data_end = crlf_pos;
//                 int data_length = data_end - start;

//                 // Ensure the chunk size matches the expected data length
//                 // (Optional: Add validation if necessary)

//                 // Allocate or expand new_buffer to hold the data
//                 if (new_buffer_length + data_length > new_buffer_capacity) {
//                     // Increase capacity (e.g., double the size or set to required size)
//                     new_buffer_capacity = (new_buffer_length + data_length) * 2;
//                     char *temp = realloc(new_buffer, new_buffer_capacity);
//                     if (!temp) {
//                         // Allocation failed
//                         free(new_buffer);
//                         return NULL;
//                     }
//                     new_buffer = temp;
//                 }

//                 // Append the chunk data to new_buffer
//                 memcpy(new_buffer + new_buffer_length, buffer + start, data_length);
//                 new_buffer_length += data_length;

//                 // Update state to END_OF_CHUNK
//                 msg->rn_state = END_OF_CHUNK;

//                 // Move position past "\r\n"
//                 pos = crlf_pos + 2;
//                 start = pos;
//             }
//         } else {
//             // No more "\r\n" found in the buffer
//             if (msg->rn_state == END_OF_CHUNK) {
//                 // Incomplete chunk size line, store the remaining data
//                 // (Optional: Handle incomplete lines by storing in msg->header or similar)
//                 // For simplicity, we'll ignore incomplete data in this implementation
//                 break;
//             } else if (msg->rn_state == END_OF_HEADER) {
//                 // Incomplete chunk data, append whatever is available
//                 int data_length = *buffer_size - start;

//                 // Allocate or expand new_buffer to hold the data
//                 if (new_buffer_length + data_length > new_buffer_capacity) {
//                     // Increase capacity
//                     new_buffer_capacity = (new_buffer_length + data_length) * 2;
//                     char *temp = realloc(new_buffer, new_buffer_capacity);
//                     if (!temp) {
//                         // Allocation failed
//                         free(new_buffer);
//                         return NULL;
//                     }
//                     new_buffer = temp;
//                 }

//                 // Append the available chunk data to new_buffer
//                 memcpy(new_buffer + new_buffer_length, buffer + start, data_length);
//                 new_buffer_length += data_length;

//                 // Update position
//                 pos = *buffer_size;
//                 start = pos;
//             }
//         }
//     }

//     // After processing all chunks, prepend a single chunk header to new_buffer
//     // Convert new_buffer_length to hexadecimal string
//     char final_chunk_header[32];
//     int header_length = snprintf(final_chunk_header, sizeof(final_chunk_header), "%X\r\n", new_buffer_length);
//     if (header_length < 0) {
//         // snprintf failed
//         free(new_buffer);
//         return NULL;
//     }

//     // Calculate total size: header + data + final "\r\n"
//     int total_size = header_length + new_buffer_length + 2;
//     char *final_buffer = malloc(total_size);
//     if (!final_buffer) {
//         // Allocation failed
//         free(new_buffer);
//         return NULL;
//     }

//     // Copy the header
//     memcpy(final_buffer, final_chunk_header, header_length);

//     // Copy the data
//     memcpy(final_buffer + header_length, new_buffer, new_buffer_length);

//     // Append the final "\r\n"
//     final_buffer[header_length + new_buffer_length] = '\r';
//     final_buffer[header_length + new_buffer_length + 1] = '\n';

//     // Free the intermediate new_buffer
//     free(new_buffer);

//     // Handle the edge case where the original buffer contained "0\r\n\r\n"
//     if (done) {
//         // Allocate space for "0\r\n\r\n"
//         char *end_chunk = "0\r\n\r\n";
//         int end_chunk_length = 5;

//         // Reallocate final_buffer to append "0\r\n\r\n"
//         final_buffer = realloc(final_buffer, total_size + end_chunk_length);
//         if (!final_buffer) {
//             // Allocation failed
//             return NULL;
//         }

//         // Append "0\r\n\r\n" to indicate the end of chunks
//         memcpy(final_buffer + total_size, end_chunk, end_chunk_length);
//         total_size += end_chunk_length;
//     }

//     // Set the output size
//     *output_size = total_size;

//     return final_buffer;
// }

bool is_request(char *buffer) {
    if (buffer == NULL) {
        return false;
    }
    if (strncmp(buffer, "GET", 3) == 0 || strncmp(buffer, "POST", 4) == 0 || strncmp(buffer, "PUT", 3) == 0 || strncmp(buffer, "DELETE", 6) == 0) {
        return true;
    }
    return false;
}

// char *make_chunk_header_and_end(char *buffer_only_data, int *data_length) {
//     char chunk_header[20];
//     sprintf(chunk_header, "%X\r\n", *data_length);
//     char *chunked_data = malloc(strlen(chunk_header) + *data_length + 3); // +3 for \r\n and null terminator
//     strcpy(chunked_data, chunk_header);
//     memcpy(chunked_data + strlen(chunk_header), buffer_only_data, *data_length);
//     strcat(chunked_data, "\r\n");
//     *data_length = *data_length + strlen(chunk_header) + 2;
//     free(buffer_only_data);

//     return chunked_data;
// }
char *make_chunk_header_and_end(char *buffer_only_data, int *data_length) {
    char chunk_header[20];
    sprintf(chunk_header, "%X\r\n", *data_length);

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
    // if (contains_chunk_end(chunked_data, chunk_header_len)) {
    //     printf("\n1 BUFFER CONTAINS END OF MESSAGE\n");
    // }
    memcpy(chunked_data + chunk_header_len, buffer_only_data, *data_length);
    // if (contains_chunk_end(chunked_data, chunk_header_len + *data_length)) {
    //     printf("\n2 BUFFER CONTAINS END OF MESSAGE\n");
    // }

    chunked_data[chunk_header_len + *data_length] = '\r';
    chunked_data[chunk_header_len + *data_length + 1] = '\n';
    chunked_data[chunk_header_len + *data_length + 2] = '\0';

    if (contains_chunk_end(chunked_data, chunk_header_len + *data_length + 2)) {
        printf("\n3 BUFFER CONTAINS END OF MESSAGE\n");
        printf("chunked_data[chunk_header_len + *data_length - 3]: %d\n", chunked_data[chunk_header_len + *data_length - 3]);
    printf("chunked_data[chunk_header_len + *data_length - 2]: %d\n", chunked_data[chunk_header_len + *data_length - 2]);
    printf("chunked_data[chunk_header_len + *data_length - 1]: %d\n", chunked_data[chunk_header_len + *data_length - 1]);
    printf("chunked_data[chunk_header_len + *data_length]: %d\n", chunked_data[chunk_header_len + *data_length - 0]);
    printf("chunked_data[chunk_header_len + *data_length + 1]: %d\n", chunked_data[chunk_header_len + *data_length + 1]);
    printf("chunked_data[chunk_header_len + *data_length + 2]: %d\n", chunked_data[chunk_header_len + *data_length + 2]);

    }

    
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
        printf("\nread ended with slash r\n");
        if (buffer[0] == '\n') {
            printf("\nbuffer starts with slash n\n");
            if (buffer_size >= 3 && buffer[1] == '\r' && buffer[2] == '\n') {
                printf("\nbuffer contains end of message\n");
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
    
    // printf("PROCESSING CHUNKED DATA\n");
    char *new_buffer = NULL;
    *output_buffer_size = 0;
    char *rn_ptr = find_next_rn(buffer, buffer_size);
    char *last_rn_ptr = buffer;
    bool done = false;

printf("\n\n\nBUFFER SIZE: %d\n", buffer_size);
// printf("rn_state: %d\n", msg->rn_state);
if (msg->rn_state == END_OF_CHUNK) {
    printf("END OF CHUNK\n");
}
else if (msg->rn_state == END_OF_HEADER) {
    printf("END OF HEADER\n");
}
        for (int i = 0; i < buffer_size; i++) {
            if (buffer[i] == '\r') {
                printf("\nslash r\n");
            }
            else if (buffer[i] == '\n') {
                printf("\nslash n\n");
            }
            else if (buffer[i] == '\0') {
                printf("\nnull terminator\n");
            }
            else {
                printf("%d", buffer[i]);
            }
        }

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

            // if (curr_chunk_size > 0) {
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

                // printf("output_buffer_size before: %X\n", *output_buffer_size);
                *output_buffer_size += curr_chunk_size;
                // printf("output_buffer_size after: %X\n", *output_buffer_size);
            // }

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
                    printf("\nlast char is slash r\n");
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

    // if (new_buffer[*output_buffer_size - 1] == '\n' && new_buffer[*output_buffer_size - 2] == '\r') {
    //     printf("\nnew buffer contains end of message\n");
    // }
    // printf("output_buffer_size: %d\n", *output_buffer_size);
    // if (*output_buffer_size > 1) {
    //     printf("new_buffer[*output_buffer_size - 1]: %d\n", new_buffer[*output_buffer_size - 1]);
    //     printf("new_buffer[*output_buffer_size - 2]: %d\n", new_buffer[*output_buffer_size - 2]);
    // }

    char *to_send = NULL;
    if (new_buffer != NULL) {
        to_send = make_chunk_header_and_end(new_buffer, output_buffer_size);
    }
    // else {
    //     *output_buffer_size = 5;
    //     to_send = malloc(5 + 1);
    //     strcpy(to_send, "0\r\n\r\n");
    // }

    // if (contains_chunk_end(to_send, *output_buffer_size)) {
    //     printf("\n2 BUFFER CONTAINS END OF MESSAGE\n");
    //     // printf("BUFFER: %s\n", buffer);
    //     to_send = add_end_of_message_chunk(to_send, output_buffer_size);
    // }

    
    return to_send;
}