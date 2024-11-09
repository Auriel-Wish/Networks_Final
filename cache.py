from utils import *

class CacheKey:
    def __init__(self, url, client_address):
        self.url = url
        self.client_address = client_address
    
    def __eq__(self, other):
        if isinstance(other, CacheKey):
            return self.url == other.url and self.client_address == other.client_address
        return False

    def __hash__(self):
        return hash((self.url, self.client_address))

class CacheValue:
    def __init__(self, text, time_saved):
        self.text = text
        self.time_saved = time_saved

def cache_server(port):
    cache = {}

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('localhost', port))

    print(f"Server listening on port {port}")

    while True:
        # Receive the request from the client
        request, a2_address = server_socket.recvfrom(BUFFER_SIZE)
        print(f"Received request from {a2_address}: {request}")

        request_line = request.decode().split('\r\n')[0]
        _, url, _ = request_line.split()

        response = None
        headers = request.decode().split('\r\n')[1:]
        client_address = None

        for header in headers:
            if header.startswith("X-Original-Client-Address:"):
                client_address = header.split(":")[1].strip()
                break
        cache_key = CacheKey(url, client_address)
        # Check if the URL is in the cache
        if cache_key in cache:
            if time.time() - cache[cache_key].time_saved > TIMEOUT:
                del cache[cache_key]
            else:
                response = cache[cache_key].text
        
        if response is not None:
            response = response.encode()
            server_socket.sendto(response, a2_address)
        else:
            context = ssl.create_default_context()
            with socket.create_connection((url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=url) as ssock:
                    ssock.sendall(request)

                    response = b""
                    while True:
                        data = ssock.recv(BUFFER_SIZE)
                        if not data:
                            break
                        response += data

            response = response.decode()

            response_line = response.split('\r\n')[0]
            _, status_code, _ = response_line.split()

            if status_code == "200":
                for key in list(cache):
                    if time.time() - cache[key].time_saved > TIMEOUT:
                        del cache[key]

                cache_value = CacheValue(response, time.time())

                if len(cache) >= CACHE_SIZE:
                    oldest_cache_key = min(cache, key=lambda k: cache[k].time_saved)
                    del cache[oldest_cache_key]
                cache[cache_key] = cache_value

            server_socket.sendto(response.encode(), a2_address)

    server_socket.close()

if __name__ == '__main__':
    cache_server(PORT)