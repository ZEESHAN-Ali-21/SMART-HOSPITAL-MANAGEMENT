import socket
import threading

HOST = "127.0.0.1"
PORT = 9000

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client.connect((HOST, PORT))

name = input("Enter your name: ")


def receive_messages():
    while True:
        try:
            message = client.recv(1024).decode()

            if message:
                print("\nReceived:", message)

        except:
            break


threading.Thread(
    target=receive_messages,
    daemon=True
).start()


while True:
    message = input()

    if message.lower() == "exit":
        break

    full_message = name + ": " + message

    client.sendall(full_message.encode())


client.close()