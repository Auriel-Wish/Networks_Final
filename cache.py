from utils import *

class CacheKey:
    def __init__(self, full_url, client_address):
        self.full_url = full_url
        self.client_address = client_address
    
    def __eq__(self, other):
        if isinstance(other, CacheKey):
            return self.full_url == other.full_url and self.client_address == other.client_address
        return False

    def __hash__(self):
        return hash((self.full_url, self.client_address))

class CacheValue:
    def __init__(self, text, time_saved):
        self.text = text
        self.time_saved = time_saved

def cache_server(port):
    cache = {}

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('10.4.2.20', port))

    print(f"Cache listening on port {port}")

    while True:
        # Receive the request from the client
        request, a2_address = server_socket.recvfrom(BUFFER_SIZE)
        headers = request.decode().split('\r\n')[1:]
        print(f"Received request from {a2_address}: {request}")
        print_cache(cache)

        request_line = request.decode().split('\r\n')[0]
        _, sub_url, _ = request_line.split()
        host = None
        for header in headers:
            if header.startswith("Host:"):
                host = header.split(":")[1].strip()
            break

        if host is not None:
            full_url = f"{host}{sub_url}"

        response = None
        client_address = None

        for header in headers:
            if header.startswith("X-Original-Client-Address:"):
                client_address = header.split(":")[1].strip()
                break
        cache_key = CacheKey(full_url, client_address)
        # Check if the URL is in the cache
        if cache_key in cache:
            if time.time() - cache[cache_key].time_saved > TIMEOUT:
                del cache[cache_key]
            else:
                response = cache[cache_key].text
        
        if response is not None:
            with open("in_cache.txt", "w") as f:
                f.write(response)
            print(f"Responding with cached response:\n{response}")
            server_socket.sendto(response.encode(), a2_address)
        else:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.sendall(request)

                    response = b""
                    while True:
                        data = ssock.recv(BUFFER_SIZE)
                        if not data:
                            break
                        response += data

            response = response.decode()

            response_line = response.split('\r\n')[0]
            if "200" in response_line:
                for key in list(cache):
                    if time.time() - cache[key].time_saved > TIMEOUT:
                        del cache[key]

                cache_value = CacheValue(response, time.time())

                if len(cache) >= CACHE_SIZE:
                    oldest_cache_key = min(cache, key=lambda k: cache[k].time_saved)
                    del cache[oldest_cache_key]
                cache[cache_key] = cache_value

            print(f"Responding with fresh response:\n{response}")
            with open("not_in_cache.txt", "w") as f:
                f.write(response)
            server_socket.sendto(response.encode(), a2_address)

    server_socket.close()

def print_cache(cache):
    print("\nCache:")
    for key, value in cache.items():
        print("------------------------------")
        print(f"Key:\n{key.full_url}, {key.client_address}")
        print(f"Value:\n{value.text}")
        print(f"Time saved: {value.time_saved}")
        print("------------------------------")
        print()
    print()

if __name__ == '__main__':
    cache_server(PORT)