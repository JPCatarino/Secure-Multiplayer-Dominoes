import sys
import selectors
import json
import io
import struct
import os
import time

sys.path.append(os.path.abspath(os.path.join('.')))
sys.path.append(os.path.abspath(os.path.join('..')))

import utils.Colors as Colors


class Message:
    def __init__(self, selector, sock, addr, game, player_list):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self.game = game
        self.player_list = player_list
        self._recv_buffer = b""
        self._send_buffer = b""
        self.request = None
        self.response_created = False
        self._response_sent = False

    def process_events(self, mask):
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()

    def read(self):
        self._read()
        if self._recv_buffer:
            self.process_request()

    def write(self):
        if self.request:
            if not self.response_created:
                self.create_response()
        self._write()
        self.response_created = False

    def close(self):
        print("closing connection to", self.addr)
        try:
            self.selector.unregister(self.sock)
        except Exception as e:
            print(
                "error: selector.unregister() exception for",
                f"{self.addr}: {repr(e)}",
            )
        try:
            self.sock.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f"{self.addr}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self.sock = None

    def process_request(self):
        data = self._recv_buffer
        self._recv_buffer = b""
        print("Processing request")
        self.request = self._json_decode(data, "utf-8")
        self._set_selector_events_mask("w")

    def create_response(self):
        response = self._create_response_json_content()
        message = self._create_message(response["content_bytes"])
        self.response_created = True
        self._send_buffer += message

    # -----------------------------------------------------------Private Methods------------------------------------------------------------------
    def _set_selector_events_mask(self, mode):
        """Set selector to listen for events: mode is 'r', 'w', or 'rw'."""
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
            (print("setting write mode"))
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError(f"Invalid events mask mode {repr(mode)}.")
        self.selector.modify(self.sock, events, data=self)

    def _read(self):
        try:
            # Should be ready to read
            data = self.sock.recv(4096)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._recv_buffer += data
            else:
                raise RuntimeError("Peer closed.")

    def _write(self):
        if self._send_buffer:
            print("sending", repr(self._send_buffer), "to", self.addr)
            try:
                # Should be ready to write
                sent = self.sock.send(self._send_buffer)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]

    def forced_write(self, message):
        print("sending", message, "to", self.addr)
        try:
            # Should be ready to write
            buffer = b""
            buffer += self._json_encode(message, "utf-8")
            self.sock.send(buffer)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass

    def _json_encode(self, obj, encoding):
        return json.dumps(obj, ensure_ascii=False).encode(encoding)

    def _json_decode(self, json_bytes, encoding):
        tiow = io.TextIOWrapper(io.BytesIO(json_bytes), encoding=encoding, newline="")
        obj = json.load(tiow)
        tiow.close()
        return obj

    def _create_message(self, content_bytes):
        message = content_bytes
        return message

    def _handle_hello(self):
        msg = {"action": "login", "msg": "Welcome to the server, what will be your name?"}
        return msg

    def _handle_login(self):
        print("User {} requests login, with nickname {}".format(self.sock.getpeername(), self.request.get("msg")))
        if not self.game.hasHost():  # There is no game for this tabla manager
            self.game.addPlayer(self.request.get("msg"), self.sock, self.game.deck.pieces_per_player)  # Adding host
            msg = {"action": "you_host", "msg": Colors.BRed + "You are the host of the game" + Colors.Color_Off}
            print("User " + Colors.BBlue + "{}".format(
                self.request.get("msg")) + Colors.Color_Off + " has created a game, he is the first to join")
            return msg
        else:
            if not self.game.hasPlayer(self.request.get("msg")):
                if self.game.isFull():
                    msg = {"action": "full", "msg": "This table is full"}
                    print("User {} tried to join a full game".format(self.request.get("msg")))
                    return msg
                else:
                    self.game.addPlayer(self.request.get("msg"), self.sock, self.game.deck.pieces_per_player)  # Adding player
                    msg = {"action": "new_player", "msg": "New Player " + Colors.BGreen + self.request.get("msg")
                                                          + Colors.Color_Off + " registered in game",
                           "nplayers": self.game.nplayers, "game_players": self.game.max_players}
                    print("User " + Colors.BBlue + "{}".format(
                        self.request.get("msg")) + Colors.Color_Off + " joined the game")

                    # send info to all players
                    self.send_all(msg)

                    # check if table is full
                    if self.game.isFull():
                        print(Colors.BIPurple + "The game is Full" + Colors.Color_Off)
                        msg = {"action": "waiting_for_host",
                               "msg": Colors.BRed + "Waiting for host to start the game" + Colors.Color_Off}
                        self.send_all(msg)
                    return msg
            else:
                msg = {"action": "disconnect", "msg": "You are already in the game"}
                print("User {} tried to join a game he was already in".format(self.request.get("msg")))
                return msg

    def _create_response_json_content(self):
        # ADD HERE MORE MESSSAGES
        print(self.request)
        action = self.request.get("action")
        if action == "hello":
            content = self._handle_hello()
            self._set_selector_events_mask("r")
        elif action == "req_login":
            content = self._handle_login()
            self._set_selector_events_mask("r")
        elif action == "Ready to play":
            print("trying to write")
            content = {"result": "Waiting for other players"}
            self._set_selector_events_mask("r")
        else:
            content = {"result": f'Error: invalid action "{action}".'}
        response = {
            "content_bytes": self._json_encode(content, "utf-8"),
        }
        return response

    def send_all(self, msg):
        for sock in self.player_list:
            if sock is not self:
                sock.forced_write(msg)