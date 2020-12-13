#!/usr/bin/env python3
import sys
import argparse
import socket
import selectors
import types

sel = selectors.DefaultSelector()

def establish_connection(host, port):
    SERVER_HOST = host
    PORT = port

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((SERVER_HOST, PORT))
    lsock.listen()
    print('Serving on ', (SERVER_HOST, PORT))
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data = None)

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                # Accept the listening socket (data is None)
                if key.data is None:
                    accept_wrapper(key.fileobj)
                # Data available. Service the connection
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print('Interrupted')
    finally:
        sel.close()


def accept_wrapper(sock):
    conn, addr = sock.accept()
    print('Connection from' , addr,  'accepted')
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, int=b'', outb=b'')
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            data.outb += recv_data
        else:
            print('Closing connection to ', data.addr)
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            print('Echoing', repr(data.outb), 'to' , data.addr)
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', type=str, help='Server IP', required=True)
    parser.add_argument('-p', '--port', type=int, help='Server Port', required=True)
    args = parser.parse_args()

    
    SERVER_HOST = args.ip
    SERVER_PORT = args.port

    establish_connection(SERVER_HOST, SERVER_PORT)
