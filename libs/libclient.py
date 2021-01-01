import sys, os
import selectors
import json
import io
import struct
import string
import random
import pickle

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
            "content_bytes": self._pickle_encode(content),
        }
        message = self._create_message(**req)
        self._send_buffer += message
        self._request_queued = True

    def process_response(self):
        data = self._recv_buffer
        self.response = self._pickle_decode(data)
        print("received response", repr(self.response), "from", self.addr)
        self._process_response_json_content()
        self._recv_buffer = b""

    # -----------------------------------------------------------Private Methods------------------------------------------------------------------

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

    def _pickle_encode(self, obj):
        return pickle.dumps(obj)

    def _pickle_decode(self, pickle_bytes):
        return pickle.loads(pickle_bytes)

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

    def _handle_waiting_for_host_as_host(self):
        input(Colors.BGreen + "PRESS ENTER TO START THE GAME" + Colors.Color_Off)
        msg = {"action": "start_game"}
        return msg

    def _handle_waiting_for_host_as_player(self):
        print(self.response.get("msg"))

    def _handle_host_start_game(self):
        print(self.response.get("msg"))
        msg = {"action": "get_game_properties"}
        return msg

    def _handle_rcv_game_properties(self):
        self.player.nplayers = self.response.get("nplayers")
        self.player.npieces = self.response.get("npieces")
        self.player.pieces_per_player = self.response.get("pieces_per_player")
        self.player.in_table = self.response.get("in_table")
        self.player.deck = self.response.get("deck")
        player_name = self.response.get("next_player")
        if self.response.get("next_player") == self.player.name:
            player_name = Colors.BRed + "YOU" + Colors.Color_Off
        print("deck -> " + ' '.join(map(str, self.player.deck)) + "\n")
        print("hand -> " + ' '.join(map(str, self.player.hand)))
        print("in table -> " + ' '.join(map(str, self.response.get("in_table"))) + "\n")
        print("Current player ->", player_name)
        print("next Action ->", self.response.get("next_action"))
        if self.player.name == self.response.get("next_player"):

            if self.response.get("next_action") == "get_piece":
                if not self.player.ready_to_play:
                    # input("Press ENter \n\n")
                    random.shuffle(self.player.deck)
                    piece = self.player.deck.pop()
                    self.player.insertInHand(piece)
                    msg = {"action": "get_piece", "deck": self.player.deck}
                    return msg
            if self.response.get("next_action") == "play":
                # input(Colors.BGreen+"Press ENter \n\n"+Colors.Color_Off)
                msg = self.player.play()
                return msg

    def _handle_end_game(self):
        winner = self.response.get("winner")
        if self.response.get("winner") == self.player.name:
            winner = Colors.BRed + "YOU" + Colors.Color_Off
        else:
            winner = Colors.BBlue + winner + Colors.Color_Off
        print(Colors.BGreen + "End GAME, THE WINNER IS: " + winner)

    def _handle_wait(self):
        print(self.response.get("msg"))

    def _handle_disconnect(self):
        self.close()
        print("PRESS ANY KEY TO EXIT ")
        sys.exit(0)

    def _process_response_json_content(self):
        # ADD CLIENT ACTIONS TO MESSAGES HERE
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
        elif action == "waiting_for_host":
            if self.player.host:
                response = self._handle_waiting_for_host_as_host()
                message = Message(self.selector, self.sock, self.addr, response, self.player)
                self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
            else:
                self._handle_waiting_for_host_as_player()
        elif action == "host_start_game":
            response = self._handle_host_start_game()
            message = Message(self.selector, self.sock, self.addr, response, self.player)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "rcv_game_properties":
            response = self._handle_rcv_game_properties()
            if response is not None:
                message = Message(self.selector, self.sock, self.addr, response, self.player)
                self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "end_game":
            self._handle_end_game()
        elif action == "wait":
            self._handle_wait()
        elif action == "disconnect":
            self._handle_disconnect()
