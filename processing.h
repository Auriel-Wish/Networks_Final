#ifndef PROCESSING_H
#define PROCESSING_H

#include "linked_list.h"

#define SCRIPT_TO_INJECT \
    "<script>" \
    "document.addEventListener('DOMContentLoaded', () => {" \
    "  const factCheckButton = document.createElement('button');" \
    "  factCheckButton.innerText = 'Run Fact Check';" \
    "  factCheckButton.style.position = 'fixed';" \
    "  factCheckButton.style.bottom = '10px';" \
    "  factCheckButton.style.right = '10px';" \
    "  factCheckButton.style.zIndex = '9999';" \
    "  factCheckButton.style.padding = '15px';" \
    "  factCheckButton.style.backgroundColor = 'white';" \
    "  factCheckButton.style.borderRadius = '5px';" \
    "  factCheckButton.style.cursor = 'pointer';" \
    "  factCheckButton.style.color = 'black';" \
    "  factCheckButton.style.border = 'none';" \
    "  factCheckButton.style.fontSize = 'large';" \
    "  factCheckButton.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';" \
    "  factCheckButton.style.transition = 'background-color 0.3s';" \
    "  factCheckButton.addEventListener('mouseover', () => {" \
    "     factCheckButton.style.backgroundColor = 'gainsboro';" \
    "  });" \
    "  factCheckButton.addEventListener('mouseout', () => {" \
    "     factCheckButton.style.backgroundColor = 'white';" \
    "  });" \
    "  document.body.appendChild(factCheckButton);" \
    "" \
    "  const toggleButton = document.createElement('button');" \
    "  toggleButton.innerText = '↑';" \
    "  toggleButton.style.position = 'fixed';" \
    "  toggleButton.style.bottom = '75px';" \
    "  toggleButton.style.right = '10px';" \
    "  toggleButton.style.zIndex = '9999';" \
    "  toggleButton.style.padding = '10px';" \
    "  toggleButton.style.backgroundColor = 'white';" \
    "  toggleButton.style.borderRadius = '5px';" \
    "  toggleButton.style.cursor = 'pointer';" \
    "  toggleButton.style.color = 'black';" \
    "  toggleButton.style.border = 'none';" \
    "  toggleButton.style.fontSize = 'large';" \
    "  toggleButton.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';" \
    "  toggleButton.style.transition = 'background-color 0.3s';" \
    "  toggleButton.addEventListener('mouseover', () => {" \
    "     toggleButton.style.backgroundColor = 'gainsboro';" \
    "  });" \
    "  toggleButton.addEventListener('mouseout', () => {" \
    "     toggleButton.style.backgroundColor = 'white';" \
    "  });" \
    "  document.body.appendChild(toggleButton);" \
    "" \
    "  let popupDiv = null;" \
    "  let is_first = true;" \
    "" \
    "  factCheckButton.addEventListener('click', async () => {" \
    "    const selection = window.getSelection().toString();" \
    "    if (selection) {" \
    "      if (!popupDiv) {" \
    "        popupDiv = document.createElement('div');" \
    "        popupDiv.style.position = 'fixed';" \
    "        popupDiv.style.top = '10%';" \
    "        popupDiv.style.left = '50%';" \
    "        popupDiv.style.transform = 'translateX(-50%)';" \
    "        popupDiv.style.maxHeight = '50%';" \
    "        popupDiv.style.overflowY = 'auto';" \
    "        popupDiv.style.padding = '20px';" \
    "        popupDiv.style.width = '60%';" \
    "        popupDiv.style.backgroundColor = 'white';" \
    "        popupDiv.style.color = 'black';" \
    "        popupDiv.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';" \
    "        popupDiv.style.zIndex = '10000';" \
    "        popupDiv.style.borderRadius = '8px';" \
    "        popupDiv.style.display = 'none';" \
    "        popupDiv.innerHTML = " \
    "          `<div style='display: flex; justify-content: space-between; align-items: center;'> " \
    "            <button id='close-button' style='background: none; border: none; font-size: 18px; cursor: pointer; color: black'>&times;</button>" \
    "          </div>" \
    "          <div id='fact-check-results'></div>`;" \
    "" \
    "        const closeButton = popupDiv.querySelector('#close-button');" \
    "        closeButton.addEventListener('click', () => {" \
    "          popupDiv.style.display = 'none';" \
    "        });" \
    "" \
    "        document.body.appendChild(popupDiv);" \
    "      }" \
    "" \
    "      popupDiv.style.display = 'block';" \
    "      const resultsContainer = popupDiv.querySelector('#fact-check-results');" \
    "" \
    "      const loadingMessage = document.createElement('p');" \
    "      loadingMessage.style.fontSize = 'large';" \
    "      loadingMessage.innerHTML = '<strong>Fact checking...<br><br></strong>';" \
    "      resultsContainer.prepend(loadingMessage);" \
    "" \
    "      try {" \
    "        const response = await fetch('https://www.quora.com/ajax/receive_POST?fact-check-CS112-Final=True', {" \
    "          method: 'POST'," \
    "          headers: { 'Content-Type': 'application/json' }," \
    "          body: JSON.stringify({ text: selection })" \
    "        });" \
    "        const result = await response.text();" \
    "        const factCheckResult = document.createElement('div');" \
    "        if (is_first) { factCheckResult.innerHTML = `<p>${result}</p>`; is_first = false; }" \
    "        else { factCheckResult.innerHTML = `<p>${result}</p><hr style='margin: 30px auto; text-align: center; border: 1px black solid; width: 80%'>`; }" \
    "        resultsContainer.prepend(factCheckResult);" \
    "        loadingMessage.remove();" \
    "      } catch (error) {" \
    "        loadingMessage.remove();" \
    "        alert('Unable to fact check. Please try again.');" \
    "      }" \
    "    }" \
    "  });" \
    "" \
    "  toggleButton.addEventListener('click', () => {" \
    "    if (popupDiv) {" \
    "      popupDiv.style.display = popupDiv.style.display === 'none' ? 'block' : 'none';" \
    "    }" \
    "  });" \
    "});" \
    "</script>"


void generate_certificates(const char *hostname);

char *convert_normal_to_chunked_encoding(char *buffer, int buffer_length, 
    incomplete_message *msg, int *chunked_data_length);

bool contains_chunk_end(char *buffer, int buffer_length);

incomplete_message *modify_header_data(incomplete_message **msg, char *buffer, 
    int filedes, Node **all_messages);

void modify_content_type(incomplete_message *msg);

void modify_accept_encoding(incomplete_message *curr_message);

char *inject_script_into_chunked_html(char *buffer, int *buffer_length);

char* process_chunked_data(incomplete_message *msg, char *buffer, int buffer_size, int *output_buffer_size);

char *add_end_of_message_chunk(char *buffer, int *buffer_length);

char *make_chunk_header_and_end(char *buffer_only_data, int *data_length);

bool is_request(char *buffer);

bool request_might_have_data(const char *method);

bool is_quora(char *hostname);

int get_content_length(char *header);

int get_content_type(char *header);

#endif

