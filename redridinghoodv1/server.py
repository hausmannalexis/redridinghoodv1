import socket
import time
import subprocess
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 6969

def start_server(SERVER_HOST, SERVER_PORT):
    server_socket = socket.socket()
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)  # Listen for incoming connections
    print(f"Listener started on {SERVER_HOST}:{SERVER_PORT}")
    time.sleep(3)

    # Clear screen based on OS
    if sys.platform == "win32":
        subprocess.run("cls", shell=True)
    else:
        subprocess.run(["clear"])

    print("Waiting for incoming connections...")
    client_socket, client_address = server_socket.accept()
    print(f"[+] {client_address} connected.")

    while True:
        try:
            command = input(">>> ")

            if not command.strip():
                continue

            client_socket.send(command.encode())  # Send command as bytes

            if command.lower() == "exit":
                print("Closing connection.")
                break
            if command.lower().startswith("help"):
                print("Commands:")
                print(" - help: Show this help message")
                print(" - exit: Close the connection")

            # Receive and print response from the client
            response = client_socket.recv(1024).decode()  # Adjust buffer size as needed
            if response:
                print(response)

        except Exception as e:
            print(f"Error: {e}")
            break

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    start_server(SERVER_HOST, SERVER_PORT)
