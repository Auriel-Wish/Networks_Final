# Fact Checker: Using an LLM Proxy to Fact-Check Quora Posts

## Introduction
This repository contains a fact-checker designed to fact-check Quora posts using a custom-built proxy and an LLM (Large Language Model). The proxy interacts with clients and servers to inject functionality into Quora pages, enabling seamless fact-checking directly within the browser.

---

## Proxy Design

### Base Proxy Design
The proxy facilitates secure communication between clients and servers while enabling multiple concurrent connections using the `select()` system call. Here’s how it works:

1. **Secure SSL Connection**:
   - The proxy pretends to be the server requested by the client by dynamically generating SSL certificates. To achieve this:
     - The proxy acts as a certificate authority.
     - It generates and signs server-specific certificates on the fly.
     - These certificates are trusted by test clients (e.g., `curl` and Firefox) after being added to the Mac system or browser's trusted certificates.

2. **Handling Client Requests**:
   - Upon receiving an HTTP CONNECT request, the proxy establishes a connection with the target server and relays data bidirectionally between the client and server.
   - All connections are managed through a set of socket file descriptors, allowing the proxy to handle multiple requests efficiently.

3. **Request and Response Processing**:
   - Requests to Quora are inspected for the `?fact-checker=true` parameter to trigger fact-check functionality.
   - Responses from Quora are re-chunked for seamless streaming while allowing the proxy to inject fact-checker scripts.

---

## LLM-Based Features

### Fact-Checker Functionality
The fact-checker is specifically designed for Quora and functions as follows:

1. **Script Injection**:
   - When a Quora page is loaded, the proxy injects a JavaScript snippet that adds a fact-check button to the browser.
   - Clicking this button sends a POST request containing highlighted text for fact-checking.

2. **Processing Requests**:
   - The proxy forwards the highlighted text to the Python-based LLM component.
   - The workflow includes:
     1. Checking if the text makes sense to fact-check using GPT-4o-mini.
     2. Generating a Wikipedia search query based on the text.
     3. Querying Wikipedia’s API for relevant articles.
     4. If articles are found, using GPT to fact-check the text against them.
     5. If no articles are found, iteratively refining the search query or asking GPT to fact-check without sources, labeling the response as unverified.

3. **Limitations**:
   - The fact-checker only works on Quora due to security and technical constraints.
   - It performs best with well-known, factual statements likely to be found on Wikipedia.
   - Context-dependent or obscure statements may reduce accuracy, especially if surrounding context is missing.

---

## Key Features
- **End-to-End Proxy with SSL**:
  - Dynamically creates and manages SSL connections between clients and servers.
  - Handles encrypted traffic transparently.

- **LLM-Driven Fact-Checking**:
  - Leverages GPT-4o-mini for intelligent text processing and Wikipedia API integration.
  - Iterative search refinement ensures comprehensive fact-checking.

- **Quora-Specific Integration**:
  - Injects custom scripts into Quora pages to enable browser-based fact-checking.

---

## Performance Considerations
- **Accuracy**:
  - Works best with factual statements and known data.
  - Struggles with opinionated, nonsensical, or poorly contextualized text.
  
- **Speed**:
  - Faster responses for statements that cannot be fact-checked.
  - Wikipedia-based fact-checking introduces additional latency due to iterative queries.

- **Security**:
  - Script injection and proxy functionality are limited to Quora for safety and compatibility reasons.

---

## Future Improvements
While the current implementation is Quora-specific, the design can be adapted to work with other platforms. Potential areas for enhancement include:
- Expanding script injection capabilities.
- Improving LLM prompt generation for more accurate and context-aware fact-checking.
- Adding support for other text sources beyond Wikipedia.

---

## How to Use
1. Clone the repository
2. pip install requirements.txt
3. Add the generated certificate authority to your system’s trusted certificates. These must be named Networks_Final_Project.crt and Networks_Final_Project.key
4. chmod +x run.sh
5. ./run.sh
6. Highlight text on Quora and click the fact-check button.

## Authors
Developed by Auriel Wish and Liam Drew
