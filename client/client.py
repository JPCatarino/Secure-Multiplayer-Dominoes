#!/usr/bin/env python3
import socket
import argparse

from random import randint

CLIENT_HOST = socket.gethostbyname(socket.gethostname())
CLIENT_PORT = randint(10000, 50000)  # TODO find a better way to attribute a port to a client
SERVER_HOST = None
SERVER_PORT = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', default="Guest", help='Username')
    parser.add_argument('-i', '--ip', type=str, help='Server IP', required=True)
    parser.add_argument('-p', '--port', type=int, help='Server Port', required=True)
    args = parser.parse_args()

    SERVER_HOST = args.ip
    SERVER_PORT = args.port

    server_address = (SERVER_HOST, SERVER_PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(server_address)

        try:
            message = b'Hello World!'
            sock.sendall(message)

        finally:
            sock.close()

