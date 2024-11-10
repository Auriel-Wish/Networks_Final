import socket

def send_request(host='10.4.2.20', port=9151):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")

        # Prepare an HTTP GET request
        http_request = "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(host)
        
        # Send the HTTP GET request to the server
        client_socket.sendall(http_request.encode('utf-8'))
        print("HTTP GET request sent")

        # Receive the response data from the server
        response = b""
        while True:
            # Receive data in chunks of 1024 bytes
            data = client_socket.recv(1024)
            if not data:
                break
            response += data

        # Decode and print the response
        print("Response received from server:")
        print(response.decode('utf-8'))
    
    except socket.error as e:
        print(f"Socket error: {e}")
    
    finally:
        # Close the connection
        client_socket.close()
        print("Connection closed")

if __name__ == '__main__':
    send_request()