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
from dominoes.game import Game
from security.asymCiphers import RSAKeychain
import utils.Colors as Colors

sel = selectors.DefaultSelector()
player_list = []
player_keys_dict = {}
player_keys_dict_PEM = {}
SERVER_KEYCHAIN = RSAKeychain()
SIGNED_NICKS = {}
CERTS = open("CCCerts.crt", 'rb').read()
SCORE = 0

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
    print(Colors.BRed + "A new client connected -> " + Colors.BGreen + "{}".format(
        addr) + Colors.Color_Off)
    conn.setblocking(False)
    message = Message(sel, conn, addr, GAME, player_list, SERVER_KEYCHAIN, player_keys_dict, player_keys_dict_PEM, SIGNED_NICKS, CERTS, SCORE)
    player_list.append(message)
    sel.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', type=str, help='Server IP', required=True)
    parser.add_argument('-p', '--port', type=int, help='Server Port', required=True)
    parser.add_argument('-np', '--num_players', type=int, help='Number of players', required=False, nargs='?', const=3)
    args = parser.parse_args()

    SERVER_HOST = args.ip
    SERVER_PORT = args.port

    if args.num_players is not None:
        GAME = Game(args.num_players)
        nplayers = args.num_players
    else:
        GAME = Game(4)
        nplayers = args.num_players

    establish_connection(SERVER_HOST, SERVER_PORT)
