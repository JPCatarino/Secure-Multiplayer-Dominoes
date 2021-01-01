import sys, os
import selectors
import json
import io
import struct
import string
import random

sys.path.append(os.path.abspath(os.path.join('.')))
sys.path.append(os.path.abspath(os.path.join('..')))

from dominoes.deck_utils import Player
from utils import Colors as Colors



class Message:
    def __init__(self, selector, sock, addr, request, player):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self.player = player
        self.request = request
        self._recv_buffer = b""
        self._send_buffer = b""
        self._request_queued = False
        self.response = None


    def process_events(self, mask):
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()

    def read(self):
        self._read()
        self.process_response()

    def write(self):
        if not self._request_queued:
            self.queue_request()

        self._write()

        if self._request_queued:
            if not self._send_buffer:
                # Set selector to listen for read events, we're done writing.
                self._set_selector_events_mask("r")

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

    def queue_request(self):
        if "content" in self.request:
            content = self.request["content"]
        elif "action" in self.request:
            content = self.request
        req = {
            "content_bytes": self._json_encode(content, "utf-8"),
        }
        message = self._create_message(**req)
        self._send_buffer += message
        self._request_queued = True

    def process_response(self):
        data = self._recv_buffer
        self.response = self._json_decode(data, "utf-8")
        print("received response", repr(self.response), "from", self.addr)
        self._process_response_json_content()
        self._recv_buffer = b""

#-----------------------------------------------------------Private Methods------------------------------------------------------------------

    def _set_selector_events_mask(self, mode):
        """Set selector to listen for events: mode is 'r', 'w', or 'rw'."""
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
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

    def _create_request(self, action):
        return dict(content=dict(action=action))

    def _handle_login(self):
        nickname = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))  # input(data["msg"])
        print("Your name is " + Colors.BBlue + nickname + Colors.Color_Off)
        msg = {"action": "req_login", "msg": nickname}
        self.player = Player(nickname, self.sock)
        return msg

    def _handle_you_host(self):
        self.player.host = True

    def _handle_new_player(self):
        print(self.response.get("msg"))
        print("There are " + str(self.response.get("nplayers")) + "\\" + str(self.response.get("game_players")))

    def _process_response_json_content(self):
        #ADD CLIENT ACTIONS TO MESSAGES HERE
        content = self.response
        action = content.get("action")
        if action == "login":
            response = self._handle_login()
            message = Message(self.selector, self.sock, self.addr, response, self.player)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "you_host":
            self._handle_you_host()
        elif action == "new_player":
            self._handle_new_player()