#!/usr/bin/env python3
import socket
import argparse
import asyncio

SERVER_HOST = None
SERVER_PORT = None


async def tcp_echo_client(message):
    reader, writer = await asyncio.open_connection(
        SERVER_HOST, SERVER_PORT)
    counter = 0
    while counter != 3:
        input()
        print(f'Send: {message!r}')
        writer.write(message.encode())

        data = await reader.read(100)
        print(f'Received: {data.decode()!r}')
        counter+=1

    print('Close the connection')
    writer.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', default="Guest", help='Username')
    parser.add_argument('-i', '--ip', type=str, help='Server IP', required=True)
    parser.add_argument('-p', '--port', type=int, help='Server Port', required=True)
    args = parser.parse_args()

    SERVER_HOST = args.ip
    SERVER_PORT = args.port

    asyncio.run(tcp_echo_client('Hello World!'))