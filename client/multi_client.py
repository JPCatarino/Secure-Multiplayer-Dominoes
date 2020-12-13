#!/usr/bin/env python3

import sys
import argparse
import socket
import selectors
import types

from client.ClientMessage import Message 

sel = selectors.DefaultSelector()

def start_connections(host, port, request):
    server_addr = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.connect_ex(server_addr)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    message = Message(sel, sock, server_addr, request)
    sel.register(sock, events, data=message)

    try:
        while True:
            events = sel.select(timeout=None)
            if events:
                for key, mask in events:
                    service_connection(key, mask)
            if not sel.get_map():
                break
    except KeyboardInterrupt:
        print('Interrupted')
    finally:
        sel.close()

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            print('Received', repr(recv_data), 'from connection', data.connid)
            data.recv_total += len(recv_data)
        """ if not recv_data or data.recv_total == data.msg_total:
            print('Closing connection', data.connid)
            sel.unregister(sock)
            sock.close() """
    if mask & selectors.EVENT_WRITE:
        if not data.outb:
            #TODO: Change here to read messages
            data.outb = 0
        if data.outb:
            print('Sending', repr(data.outb), 'to connection', data.connid)
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--connections',type=int, default="4", help='Number of connections')
    parser.add_argument('-i', '--ip', type=str, help='Server IP', required=True)
    parser.add_argument('-p', '--port', type=int, help='Server Port', required=True)
    args = parser.parse_args()


    SERVER_HOST = args.ip
    SERVER_PORT = args.port
    NUM_CONNS = args.connections

    start_connections(SERVER_HOST, SERVER_PORT, NUM_CONNS)