#!/usr/bin/env python3
import socket

HOST = socket.gethostbyname(socket.gethostname())
PORT = 12345


def message_handler(new_message, address):
    print(address)
    print(new_message)


if __name__ == "__main__":
    server_address = (HOST, PORT)
    print(server_address)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(server_address)
        sock.listen()
        conn, addr = sock.accept()

        # For now the server closes after one connection, this behaviour shall change later
        with conn:
            try:
                while True:
                    data = conn.recv(1024)

                    if data:
                        message_handler(data, addr)
                    else:
                        break

            finally:
                conn.close()
