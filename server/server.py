#!/usr/bin/env python3
import socket
import asyncio

HOST = socket.gethostbyname(socket.gethostname())
PORT = 12345

numberOfClients = 0


async def handle_echo(reader, writer):
    counter = 0
    global numberOfClients
    numberOfClients += 1

    while counter != 3:
        print(numberOfClients)
        data = await reader.read(100)
        message = data.decode()
        addr = writer.get_extra_info('peername')

        print(f"Received {message!r} from {addr!r}")

        print(f"Send: {message!r}")
        writer.write(data)
        await writer.drain()
        counter += 1

    print("Close the connection")
    writer.close()
    numberOfClients -= 1


async def main():
    server = await asyncio.start_server(
        handle_echo, HOST, PORT)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()


asyncio.run(main())
