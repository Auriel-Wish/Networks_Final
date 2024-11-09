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
    server_socket.bind(('10.4.2.20', port))

    print(f"Server listening on port {port}")

    while True:
        # Receive the request from the client
        request, a2_address = server_socket.recvfrom(BUFFER_SIZE)
        print(f"Received request from {a2_address}: {request}")
        print_cache(cache)

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
            print(f"Responding with cached response: {response}")
            server_socket.sendto(response, a2_address)
        else:
            print("SENDING TOO SERVER")
            context = ssl.create_default_context()
            print("0 here")
            print(url)
            with socket.create_connection((url, 443)) as sock:
                print("anothe here")
                with context.wrap_socket(sock, server_hostname=url) as ssock:
                    print("1")
                    ssock.sendall(request)
                    print("2")


                    response = b""
                    while True:
                        print("3")
                        data = ssock.recv(BUFFER_SIZE)
                        print("4")
                        if not data:
                            break
                        response += data

            response = response.decode()

            response_line = response.split('\r\n')[0]
            _, status_code, _ = response_line.split()

            print("5")

            if status_code == "200":
                for key in list(cache):
                    if time.time() - cache[key].time_saved > TIMEOUT:
                        del cache[key]

                cache_value = CacheValue(response, time.time())

                if len(cache) >= CACHE_SIZE:
                    oldest_cache_key = min(cache, key=lambda k: cache[k].time_saved)
                    del cache[oldest_cache_key]
                cache[cache_key] = cache_value

            print(f"Responding with fresh response: {response}")
            server_socket.sendto(response.encode(), a2_address)

    server_socket.close()

def print_cache(cache):
    print("Cache:")
    for key, value in cache.items():
        print(f"Key: {key.url}, {key.client_address}")
        print(f"Value: {value.text}")
        print(f"Time saved: {value.time_saved}")
        print()

if __name__ == '__main__':
    cache_server(PORT)