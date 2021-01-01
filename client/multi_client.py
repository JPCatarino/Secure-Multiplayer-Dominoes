#!/usr/bin/env python3

import sys
import argparse
import socket
import selectors
import traceback
import os

# Uncomment this if you're having trouble with module not found
sys.path.append(os.path.abspath(os.path.join('.')))
sys.path.append(os.path.abspath(os.path.join('..')))

from libs.libclient import Message 

sel = selectors.DefaultSelector()
PLAYER = None

def start_connections(host, port):
    addr = (host, port)
    print("starting connection to", addr)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.connect_ex(addr)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    request = create_request("hello")
    message = Message(sel, sock, addr, request, PLAYER)
    sel.register(sock, events, data=message)

def create_request(action):
    return dict(content=dict(action=action))

def service_connection():
    try:
        while True:
            events = sel.select(timeout=1)
            for key, mask in events:
                message = key.data
                try:
                    message.process_events(mask)
                    break
                except Exception:
                    print(
                        "main: error: exception for",
                        f"{message.addr}:\n{traceback.format_exc()}",
                    )
                    message.close()

            if not sel.get_map():
                break
    except KeyboardInterrupt:
        print("caught keyboard interrupt, exiting")
    finally:
        sel.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', type=str, help='Server IP', required=True)
    parser.add_argument('-p', '--port', type=int, help='Server Port', required=True)
    args = parser.parse_args()


    SERVER_HOST = args.ip
    SERVER_PORT = args.port

    start_connections(SERVER_HOST, SERVER_PORT)
    service_connection()