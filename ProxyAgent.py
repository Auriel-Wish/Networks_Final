import json
from websocket import create_connection, WebSocketConnectionClosedException
from flask import Flask, request, jsonify

# Read proxy config from config.json
with open('config.json', 'r') as file:
    config_proxy_agent = json.load(file)

end_point = config_proxy_agent['endPoint']
api_key = config_proxy_agent['apiKey']
port = int(config_proxy_agent['port'])
address = config_proxy_agent['address']

ws = create_connection(end_point, header=[f"x-api-key: {api_key}"])


def ProxyRequest(request_data):

    # adding route for backend websocket
    request_data['action'] = 'ProxyRequest'

    ws.send(json.dumps(request_data))
    
    response = ws.recv()


    if "timed out" in response:
        response = ws.recv()

    return json.loads(response)

app = Flask(__name__)

@app.route('/post', methods=['POST'])
def handle_post():
    # Get JSON data from the request
    request_data = request.get_json()

    try:
        proxy_response = ProxyRequest(request_data)
    except WebSocketConnectionClosedException:
        print("socket was closed - reconnecting")
        ws = create_connection(end_point, header=[f"x-api-key: {api_key}"])
        proxy_response = ProxyRequest(request_data)
    except Exception as e:
        raise e
    
    result = proxy_response.get('result', "None")

    # Example response
    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=False, host=address, port=port)