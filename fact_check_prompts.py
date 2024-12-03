make_query_prompt = '''
You will be given a piece of text that may or may not be true.
The goal is to find Wikipedia articles related to the topic and verify the information.
You're job is to return a Wikipedia query that, when we submit the query to
the Wikipedia API, will help me find relevant articles. ONLY RETURN THE QUERY ITSELF.
'''

verify_information_prompt = '''
You will be given a piece of text that may or may not be true.
You will also be given a Wikipedia article that is accepted to be true.
Your job is to compare the information in the text with the information in the Wikipedia article.
Return an explanation of whether the text is true or false, and provide evidence to support your conclusion.
'''