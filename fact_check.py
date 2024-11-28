import wikipedia
import time
from fact_check_prompts import *

def search_wikipedia(query, max_results=5, delay=2):
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
            return {}

        articles_content = {}
        for title in search_results:
            try:
                print(f"Fetching content for: {title}")
                # Get the full article text
                content = wikipedia.page(title, auto_suggest=False).content
                articles_content[title] = content
                time.sleep(delay)  # Add delay between requests
            except wikipedia.DisambiguationError as e:
                print(f"Disambiguation error for '{title}': {e.options}")
            except wikipedia.PageError:
                print(f"Page '{title}' does not exist.")

        return articles_content
    except Exception as e:
        print(f"An error occurred while searching Wikipedia: {e}")
        return {}

def main():
    query = "Python programming"

    articles = search_wikipedia(query)

    if articles:
        for title, content in articles.items():
            print(f"\nTitle: {title}\n")
            print(content[:500])  # Print the first 500 characters of the article for brevity
            print("\n" + "-" * 80 + "\n")
    else:
        print("No articles were retrieved.")

if __name__ == "__main__":
    main()