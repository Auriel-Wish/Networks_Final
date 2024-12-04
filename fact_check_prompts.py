make_query_prompt = '''
You will be given a piece of text that may or may not be true.
The goal is to find Wikipedia articles related to the topic and verify the information.
You're job is to return a Wikipedia query that, when we submit the query to
the Wikipedia API, will help me find relevant articles. ONLY RETURN THE QUERY ITSELF.
'''

remake_query_prompt = '''
The previously generated queries were unsuccessful. Please try again from a different perspective.
Try to generalize the query. For example, if the text to fact check is about cheese nutritional facts,
a good general query would be "cheese nutrition", or even "cheese". 
Previous (unsuccessful) queries: 
'''

verify_information_prompt = '''
You will be given a piece of text that may or may not be true.
You will also be given a Wikipedia article that is accepted to be true.
Your job is to compare the information in the text with the information in the Wikipedia article.
Return an explanation of how true the claim is, and provide evidence to support your conclusion.
However, DO NOT explicity state that you are comparing the text with the Wikipedia article - 
act as if you came up with the information.
DO NOT write more than 200 words, and DO NOT waste space repeating the claim itself.
'''

verify_information_no_wiki_prompt = '''
You will be given a piece of text. Your job is to determine how true the text is.
Return your analysis and provide evidence to support your conclusion.
DO NOT write more than 200 words, and DO NOT waste space repeating the claim itself.
'''