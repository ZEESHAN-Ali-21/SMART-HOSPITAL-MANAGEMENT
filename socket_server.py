import socket
import threading

HOST = "0.0.0.0"
PORT = 9000

clients = []


def handle_client(client, address):
    print("Client connected:", address)

    clients.append(client)

    try:
        while True:
            data = client.recv(1024)

            if not data:
                break

            message = data.decode()

            print("Message:", message)

            for other_client in clients:
                if other_client != client:
                    other_client.sendall(message.encode())

    except:
        pass

    finally:
        if client in clients:
            clients.remove(client)

        client.close()

        print("Client disconnected:", address)


def start_socket_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"TCP Socket Server running on port {PORT}")

    while True:
        client, address = server.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(client, address)
        )

        thread.start()