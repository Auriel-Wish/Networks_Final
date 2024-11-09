import socket
import ssl

def send_https_request(host='10.4.2.20', port=9052):
    # Create a socket object
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Wrap the socket with SSL to secure the connection
    context = ssl.create_default_context()
    client_socket = context.wrap_socket(raw_socket, server_hostname=host)

    try:
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port} over HTTPS")

        # Prepare an HTTPS GET request
        http_request = "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(host)
        
        # Send the HTTPS GET request to the server
        client_socket.sendall(http_request.encode('utf-8'))
        print("HTTPS GET request sent")

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
    
    except (socket.error, ssl.SSLError) as e:
        print(f"Connection error: {e}")
    
    finally:
        # Close the connection
        client_socket.close()
        print("Connection closed")

if __name__ == '__main__':
    send_https_request()