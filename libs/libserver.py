import sys
import selectors
import json
import io
import struct
import os
import time
import pickle

sys.path.append(os.path.abspath(os.path.join('.')))
sys.path.append(os.path.abspath(os.path.join('..')))

import utils.Colors as Colors
from security.asymCiphers import readPublicKeyFromPEM
from security.symCiphers import AESCipher


# Main socket code from https://realpython.com/python-sockets/

class Message:
    def __init__(self, selector, sock, addr, game, player_list, keychain, player_keys_dict, player_keys_dict_PEM):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self.game = game
        self.keychain = keychain
        self.player_list = player_list
        self.player_keys_dict = player_keys_dict
        self.player_keys_dict_PEM = player_keys_dict_PEM
        self.player_aes = AESCipher()
        self.player_nickname = ""
        self.player_key = None
        self._recv_buffer = b""
        self._send_buffer = b""
        self.request = None
        self.response_created = False
        self._response_sent = False
        self.game_started = False

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
        self.request = self._pickle_decode(data)
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
            buffer += self._pickle_encode(message)
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

    def _pickle_encode(self, obj):
        return pickle.dumps(obj)

    def _pickle_decode(self, pickle_bytes):
        return pickle.loads(pickle_bytes)

    def _create_message(self, content_bytes):
        message = content_bytes
        return message

    def _handle_hello(self):
        msg = {"action": "login", "msg": "Welcome to the server, what will be your name?"}
        return msg

    def _handle_login(self):
        print("User {} requests login, with nickname {}".format(self.sock.getpeername(), self.request.get("msg")))
        self.player_nickname = self.request.get("msg")
        self.player_keys_dict_PEM[self.request.get("msg")] = self.request.get("pubkey")
        self.player_keys_dict[self.request.get("msg")] = readPublicKeyFromPEM(self.request.get("pubkey"))
        self.player_key = readPublicKeyFromPEM(self.request.get("pubkey"))
        encrypted_secret = self.keychain.encrypt(self.player_aes.secret, self.player_key)
        if not self.game.hasHost():  # There is no game for this tabla manager
            self.game.addPlayer(self.request.get("msg"), self.sock, self.game.deck.pieces_per_player)  # Adding host
            msg = {"action": "you_host", "session_key": encrypted_secret,"msg": Colors.BRed + "You are the host of the game" + Colors.Color_Off}
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
                    self.game.addPlayer(self.request.get("msg"), self.sock,
                                        self.game.deck.pieces_per_player)  # Adding player
                    msg = {"action": "new_player", "msg": "New Player " + Colors.BGreen + self.request.get("msg")
                                                          + Colors.Color_Off + " registered in game",
                           "nplayers": self.game.nplayers, "game_players": self.game.max_players}
                    print("User " + Colors.BBlue + "{}".format(
                        self.request.get("msg")) + Colors.Color_Off + " joined the game")

                    # send info to all players
                    self.send_all(msg)
                    msg["session_key"] = encrypted_secret

                    # check if table is full
                    if self.game.isFull():
                        print(Colors.BIPurple + "The game is Full" + Colors.Color_Off)
                        msg = {"action" : "key_exchange", "session_keys": self.player_keys_dict_PEM, "msg": "Establishing players secure session"}
                        self.send_all(msg)
                    return msg
            else:
                msg = {"action": "disconnect", "msg": "You are already in the game"}
                print("User {} tried to join a game he was already in".format(self.request.get("msg")))
                return msg

    def _handle_aes_exchange(self):
        if "aes_keys" in self.request:
            aes_keys= self.request.get("aes_keys")
            list_of_players = aes_keys.keys()
            for player in list_of_players:
                for player_send in aes_keys[player]:
                    temp = {}
                    temp[player] = aes_keys[player].get(player_send)
                    msg = {"action" : "receiving_aes", "aes_key" : temp, "player_receive" : player_send}
                    self.send_all(msg)       
        msg = {"action": "keys_exchanged",
            "msg": Colors.BYellow + "Keys have been exchanged" + Colors.Color_Off}
        self.send_all(msg)
        return msg
    
    def _handle_finish_setup(self):
        msg = {"action": "waiting_for_host", "msg": Colors.BRed + "Waiting for host to start the game" + Colors.Color_Off}
        return msg

    def _handle_start_game(self):
        self.game.deck.generate_pseudonymized_deck()
        msg = {"action": "host_start_game",
               "msg": Colors.BYellow + "The Host started the game" + Colors.Color_Off}
        self.game.players_ready = True
        self.send_all(msg)
        return msg

    def _handle_ready_to_play(self):
        msg = {"action": "host_start_game",
               "msg": Colors.BYellow + "The Host started the game" + Colors.Color_Off}
        self.send_all(msg)
        return msg

    def _handle_get_game_properties(self):
        msg = {"action": "rcv_game_properties"}
        msg.update(self.game.toJson())
        return msg

    def _handle_get_piece(self, player):
        self.game.deck.deck = self.request.get("deck")
        player.updatePieces(1)
        if not self.game.started:
            print("player pieces ", player.num_pieces)
            print("ALL-> ", self.game.allPlayersWithPieces())
            self.game.nextPlayer()
            if self.game.allPlayersWithPieces():
                self.game.started = True
                self.game.next_action = "play"
        msg = {"action": "rcv_game_properties"}
        msg.update(self.game.toJson())
        self.send_all(msg)
        return msg

    def _handle_play_piece(self, player):
        next_p = self.game.nextPlayer()
        if self.request.get("piece") is not None:
            player.nopiece = False
            player.updatePieces(-1)
            if self.request.get("edge") == 0:
                self.game.deck.in_table.insert(0, self.request.get("piece"))
            else:
                self.game.deck.in_table.insert(len(self.game.deck.in_table), self.request.get("piece"))

        print("player pieces ", player.num_pieces)
        print("player " + player.name + " played " + str(self.request.get("piece")))
        print("in table -> " + ' '.join(map(str, self.game.deck.in_table)) + "\n")
        print("deck -> " + ' '.join(map(str, self.game.deck.deck)) + "\n")
        if self.request.get("win"):
            if player.checkifWin():
                print(Colors.BGreen + " WINNER " + player.name + Colors.Color_Off)
                msg = {"action": "end_game", "winner": player.name}
        else:
            msg = {"action": "rcv_game_properties"}
        msg.update(self.game.toJson())
        self.send_all(msg)
        return msg

    def _handle_pass_play(self, player):
        self.game.nextPlayer()
        # If the player passed the previous move
        if player.nopiece:
            print("No piece END")
            msg = {"action": "end_game", "winner": Colors.BYellow + "TIE" + Colors.Color_Off}
        # Update the variable nopiece so that the server can know if the player has passed the previous move
        else:
            print("No piece")
            player.nopiece = True
            msg = {"action": "rcv_game_properties"}
            msg.update(self.game.toJson())

        self.send_all(msg)
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
            response = {
                "content_bytes": self._pickle_encode(content),
            }
            return response
        elif action == "aes_exchange":
            content = self._handle_aes_exchange()
            self._set_selector_events_mask("r")
        elif action == "finished_setup":
            content = self._handle_finish_setup()
            self._set_selector_events_mask("r")
        elif action == "start_game":
            content = self._handle_start_game()
            self._set_selector_events_mask("r")
        elif action == "ready_to_play":
            content = self._handle_ready_to_play()
            self._set_selector_events_mask("r")
        elif action == "get_game_properties":
            content = self._handle_get_game_properties()
            self._set_selector_events_mask("r")
        else:
            content = {"result": f'Error: invalid action "{action}".'}
        if self.game.isFull() & self.game.players_ready:
            c_player = self.game.currentPlayer()
            if self.sock == c_player.socket:
                if action == "get_piece":
                    content = self._handle_get_piece(c_player)
                    self._set_selector_events_mask("r")
                elif action == "play_piece":
                    content = self._handle_play_piece(c_player)
                    self._set_selector_events_mask("r")
                elif action == "pass_play":
                    content = self._handle_pass_play(c_player)
                    self._set_selector_events_mask("r")
            else:
                content = {"action": "wait", "msg": Colors.BRed + "Not Your Turn" + Colors.Color_Off}

        response = {
            "content_bytes": self._pickle_encode(content),
        }
        return response

    def send_all(self, msg):
        for sock in self.player_list:
            if sock is not self:
                sock.forced_write(msg)
        time.sleep(0.2)

    def send_to_player(self, player_name, msg):
        for sock in self.player_list:
            if self.player_nickname in player_name:
                sock.forced_write(msg)
        time.sleep(0.2)
