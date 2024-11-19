#CHANGE
from utils import *

class CacheKey:
    def __init__(self, full_url, original_client_fd):
        self.full_url = full_url
        self.original_client_fd = original_client_fd
    
    def __eq__(self, other):
        if isinstance(other, CacheKey):
            return self.full_url == other.full_url and self.original_client_fd == other.original_client_fd
        return False

    def __hash__(self):
        return hash((self.full_url, self.original_client_fd))

class CacheValue:
    def __init__(self, text, time_saved):
        self.text = text
        self.time_saved = time_saved

def cache_server():
    cache = {}

    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    socket_path = f"/tmp/cache_server.sock"
    if os.path.exists(socket_path):
        os.remove(socket_path)
    server_socket.bind(socket_path)
    print(f"Cache listening on path {socket_path}")

    while True:
        # Receive the request from the client
        request = b""
        client_address = None
        while True:
            data, client_address = server_socket.recvfrom(BUFFER_SIZE)
            request += data
            if b'\r\n\r\n' in request:
                req_header_length = request.index(b'\r\n\r\n') + 4
            headers = request[:req_header_length].decode().split('\r\n')
            req_content_length = -1
            for header in headers:
                if header.lower().startswith("content-length:"):
                    req_content_length = int(header.split(":")[1].strip())
                break
            if req_content_length == -1 or len(request) >= req_header_length + req_content_length:
                break
        print(f"\n\n\nRequest:\n{request}")

        print("Received Data")
        if request == b'':
            break

        port_number = int.from_bytes(request[:4], byteorder='little')
        http_request = request[4:]

        # Extract the HTTP request from the rest of the bytes
        # try:
        http_request_decoded = http_request.decode()
        # except:
        #     None
        headers = http_request_decoded.split('\r\n')[1:]
        request_line = http_request_decoded.split('\r\n')[0]
        _, sub_url, _ = request_line.split()
        host = None
        for header in headers:
            if header.startswith("Host:"):
                host = header.split(":")[1].strip()
            break

        if host is not None:
            full_url = f"{host}{sub_url}"

        response = None
        original_client_fd = None

        for header in headers:
            if header.startswith("X-Original-Client-Address:"):
                original_client_fd = int(header.split(":")[1].strip())
                break
        cache_key = CacheKey(full_url, original_client_fd)
        # Check if the URL is in the cache
        if cache_key in cache:
            if time.time() - cache[cache_key].time_saved > TIMEOUT:
                del cache[cache_key]
            else:
                response = cache[cache_key].text
        
        if response is None:
            context = ssl.create_default_context()
            print(f"Making a fresh request to {host} on port {port_number}")
            with socket.create_connection((host, port_number)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.sendall(http_request)

                    response = b""
                    content_length = -1
                    header_length = -1
                    i = 0
                    while True:
                        data = ssock.recv(BUFFER_SIZE)
                        if i < 5:
                            # print(f"\n\n\n\ndata: {data}")
                            i += 1
                        if data:
                            # print(f"Data Length: {len(data)}")
                            response += data
                            lower_case_response = response.lower()
                            if content_length == -1 and b'\r\ncontent-length:' in lower_case_response:
                                content_length = int(lower_case_response.split(b'\r\ncontent-length:')[1].split(b'\r\n')[0])
                            if header_length == -1 and b'\r\n\r\n' in response:
                                header_length = response.index(b'\r\n\r\n') + 4
                        # print(f"Response Length: {len(response)}")
                        # print(f"Content Length: {content_length}")
                        # print(f"Header Length: {header_length}")
                        if len(response) >= header_length + content_length and (content_length != -1 and header_length != -1):
                            break

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
        else:
            print("Cache hit")

        # print(f"RESPONSE:\n{response}")
        # for i in range(0, len(response), BUFFER_SIZE - 1):
        #     to_send = original_client_fd.to_bytes(1, byteorder='big') + response[i:i + BUFFER_SIZE - 1].encode()
        #     server_socket.sendto(to_send, client_address)
        i = 0
        while i < len(response):
            to_send = original_client_fd.to_bytes(1, byteorder='big') + response[i:i + BUFFER_SIZE - 1].encode()
            try:
                server_socket.sendto(to_send, client_address)
                i += BUFFER_SIZE - 1
            except OSError as e:
                if e.errno == 55:  # No buffer space available
                    print("No buffer space available, retrying...")
                    time.sleep(0.1)
                else:
                    raise  # Re-raise the exception if it's not the expected error

    server_socket.close()

def print_cache(cache):
    print("\nCache:")
    for key, value in cache.items():
        print("------------------------------")
        print(f"Key:\n{key.full_url}, {key.original_client_fd}")
        print(f"Value:\n{value.text}")
        print(f"Time saved: {value.time_saved}")
        print("------------------------------")
        print()
    print()

if __name__ == '__main__':
    cache_server()