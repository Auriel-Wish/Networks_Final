import wikipedia
import time
import json
import requests
import socket
import os
import html
from fact_check_prompts import *

MAX_ARTICLE_LENGTH = 10000

def search_wikipedia(query, max_results):
    """
    Searches for Wikipedia articles based on a query and retrieves their content.
    
    Args:
        query (str): The search query.
        max_results (int): The maximum number of results to retrieve (default is 5).
        delay (int): Delay (in seconds) between requests for rate limiting (default is 2).
    
    Returns:
        dict: A dictionary where keys are article titles and values are the text content.
    """
    wikipedia.set_lang("en")  # Set the language to English

    try:
        search_results = wikipedia.search(query, results=max_results)
        if not search_results:
            print("No articles found for the query.")
            return None

        articles_content = {}
        for title in search_results:
            try:
                # print(f"Fetching content for: {title}")
                # Get the full article text
                content = wikipedia.page(title, auto_suggest=False).content
                articles_content[title] = content
                time.sleep(0.5)  # Add delay between requests
            except wikipedia.DisambiguationError as e:
                print(f"Disambiguation error for '{title}': {e.options}")
            except wikipedia.PageError:
                print(f"Page '{title}' does not exist.")

        return articles_content
    except Exception as e:
        print(f"An error occurred while searching Wikipedia: {e}")
        return {}

def make_LLM_request(request, url):
    try:
        # print(f"Initiating request: {request}")
        response = requests.post(url, json=request)

        if response.status_code == 200:
            print("RESPONSE:")
            print(response.text)
            return (response.text[1:-2]).replace('\n', "<br>")
        else:
            print(f"Error: Received response code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return None

def get_LLM_fact_check_response(to_fact_check, url):
    request = {
        'model': '4o-mini',
        'system': make_query_prompt,
        'query': to_fact_check,
        'temperature': 0.7,
    }

    successful_wiki_query = False
    unsuccessful_wiki_queries = []

    while not successful_wiki_query:
        print("Generating Wikipedia query...")
        wiki_query = make_LLM_request(request, url)
        print(f"Wiki query: {wiki_query}")
        if not wiki_query:
            print("Wikipedia query generation unsuccessful.")
            break

        if wiki_query:
            articles = search_wikipedia(wiki_query, max_results=2)

            total_fact_check_content = ""
            if articles:
                successful_wiki_query = True

                for title, content in articles.items():
                    total_fact_check_content += f"Title: {title}\n\n"
                    total_fact_check_content += content[:MAX_ARTICLE_LENGTH]  # Limit the content length
                    total_fact_check_content += "\n\n\n"
            else:
                print("No articles were retrieved. Trying a different query...")
                unsuccessful_wiki_queries.append(wiki_query)
                request['query'] = f"{to_fact_check}\n\n{remake_query_prompt}{str(unsuccessful_wiki_queries)}"
                request['temperature'] += 0.3
                if request['temperature'] > 2.0:
                    print("Failed to generate a successful Wikipedia query.")
                    break
                continue
            
            if total_fact_check_content != "" and successful_wiki_query:
                full_query = f"Is the statement '{to_fact_check}' true?\n\n"
                full_query += f"Here is the ground truth evidence:\n\n{total_fact_check_content}"

                request = {
                    'model': '4o-mini',
                    'system': verify_information_prompt,
                    'query': full_query,
                }

                print("Fact checking the statement...")
                fact_check_response = make_LLM_request(request, url)
                if fact_check_response:
                    return fact_check_response
                
    return LLM_no_wiki_fact_check(to_fact_check, url)

def LLM_no_wiki_fact_check(to_fact_check, url):
    request = {
        'model': '4o-mini',
        'system': verify_information_no_wiki_prompt,
        'query': to_fact_check,
    }
    return "<strong>RESPONSE NOT VERIFIED BY SOURCE - POSSIBLE HALLUCINATION</strong><br>" + str(make_LLM_request(request, url))

def can_be_fact_checked(to_fact_check, url):
    request = {
        'model': '4o-mini',
        'system': possible_to_fact_check_prompt,
        'query': to_fact_check,
    }
    res = make_LLM_request(request, url)
    return ('yes' in res.lower())

def main():
    # Define the paths for the Unix domain socket
    SOCKET_PATH = "/tmp/python_dgram_socket"

    # Ensure no leftover socket file
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    # Create a Unix datagram socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        # Bind to the socket
        sock.bind(SOCKET_PATH)
        print(f"Listening on {SOCKET_PATH}...")

        with open('config.json', 'r') as file:
            config_proxy_agent = json.load(file)

        port = int(config_proxy_agent['port'])
        address = config_proxy_agent['address']
        url = f"http://{address}:{port}/post"

        # Continuous loop to wait for data
        while True:
            data, addr = sock.recvfrom(10000)
            if not data:
                print("No data received. Exiting...")
                break
            try:
                data = data.decode()
                data = json.loads(data)
            except:
                n = sock.sendto("An error occurred while fact checking.".encode(), addr)
                continue
            to_fact_check = data['text']
            # json_payload = {
            #     "factCheck": "UNKNOWN ERROR"
            # }
            to_send = None

            extra_text = to_fact_check[:100]
            if len(to_fact_check) > 100:
                extra_text += "..."
            extra_text = f"<strong>{extra_text}</strong><br><br>"

            if can_be_fact_checked(to_fact_check, url):
                LLM_response = get_LLM_fact_check_response(to_fact_check, url)
                formatted_response = f"{extra_text}{LLM_response.replace('\\n', '<br>')}"
                formatted_response = html.unescape(formatted_response)

                if formatted_response:
                    to_send = formatted_response
                else:
                    to_send = f"{extra_text}An error occurred while fact checking."
            else:
                to_send = f"{extra_text}Statement does not make sense to fact check"
            
            # json_output = json.dumps(json_payload, ensure_ascii=False)
            print(f"Sending to proxy:\n{to_send}")
            # data_to_send = json_output.encode('utf-8')
            n = sock.sendto(to_send.encode('utf-8'), addr)

    finally:
        sock.close()
        os.remove(SOCKET_PATH)

if __name__ == "__main__":
    main()