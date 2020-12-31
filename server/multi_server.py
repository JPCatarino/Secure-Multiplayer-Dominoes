#!/usr/bin/env python3
import sys
import argparse
import socket
import selectors
import types
import os
import traceback

# Uncomment this if you're having trouble with module not found
sys.path.append(os.path.abspath(os.path.join('.')))
sys.path.append(os.path.abspath(os.path.join('..')))

from libs.libserver import Message



sel = selectors.DefaultSelector()

def establish_connection(host, port):
    SERVER_HOST = host
    PORT = port

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((SERVER_HOST, PORT))
    lsock.listen()
    print("listening on", (SERVER_HOST, PORT))
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ | selectors.EVENT_WRITE, data=None)

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    message = key.data
                    try:
                        message.process_events(mask)
                    except Exception:
                        print(
                            "main: error: exception for",
                            f"{message.addr}:\n{traceback.format_exc()}",
                        )
                        message.close()
    except KeyboardInterrupt:
        print("caught keyboard interrupt, exiting")
    finally:
        sel.close()


def accept_wrapper(sock):
    conn, addr = sock.accept()
    print("accepted connection from", addr)
    conn.setblocking(False)
    message = Message(sel, conn, addr)
    sel.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', type=str, help='Server IP', required=True)
    parser.add_argument('-p', '--port', type=int, help='Server Port', required=True)
    args = parser.parse_args()

    
    SERVER_HOST = args.ip
    SERVER_PORT = args.port

    establish_connection(SERVER_HOST, SERVER_PORT)
