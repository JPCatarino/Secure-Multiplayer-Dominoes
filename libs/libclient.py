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
from security.symCiphers import AESCipher
from security.asymCiphers import readPublicKeyFromPEM
from security.handCommit import *


# Main socket code from https://realpython.com/python-sockets/

class Message:
    def __init__(self, selector, sock, addr, request, player, keychain, player_cc, aes_cipher=None):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self.player = player
        self.keychain = keychain
        self.cc = player_cc
        self.aes_cipher = aes_cipher
        self.aes_player_keys = {}
        self.exchange_aes = None
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
        signed_nick = self.cc.signData(nickname)
        cert = self.cc.get_signature_cert()
        print("Your name is " + Colors.BBlue + nickname + Colors.Color_Off)
        msg = {"action": "req_login", "pubkey": self.keychain.exportPubKey(), "msg": nickname, "signed_nick": signed_nick, "cert": cert}
        self.player = Player(nickname, self.sock)
        return msg

    def _handle_you_host(self):
        aes_secret = self.keychain.decrypt(self.response.get("session_key"))
        self.aes_cipher = AESCipher(aes_secret)
        self.player.host = True

    def _handle_new_player(self):
        if "session_key" in self.response:
            aes_secret = self.keychain.decrypt(self.response.get("session_key"))
            print(aes_secret)
            self.aes_cipher = AESCipher(aes_secret)
        print(self.response.get("msg"))
        print("There are " + str(self.response.get("nplayers")) + "\\" + str(self.response.get("game_players")))

    def _handle_key_exchange(self):
        print(self.response.get("msg"))
        if "session_keys" in self.response:
            aes_exchange_keys = {}
            aes_keys = {}
            players_pub_keys = self.response.get("session_keys")
            list_of_keys = list(players_pub_keys.keys())
            for keys in list_of_keys:
                if keys not in self.player.name:
                    self.exchange_aes = AESCipher()
                    encrypted_secret = self.keychain.encrypt(self.exchange_aes.secret,
                                                             readPublicKeyFromPEM(players_pub_keys[keys]))
                    aes_exchange_keys[keys] = encrypted_secret
                    aes_keys[self.player.name] = aes_exchange_keys
                    self.player.aes_player_keys_dec[keys] = self.exchange_aes
            msg = {"action": "aes_exchange", "aes_keys": aes_keys}
        return msg

    def _handle_receiving_aes(self):
        if "aes_key" in self.response:
            aes_key = self.response.get("aes_key")
            print(aes_key)
            if self.player.name in self.response.get("player_receive"):
                for key in aes_key:
                    self.player.aes_player_keys[key] = aes_key[key]
                    print(aes_key[key])
                    print(self.player.aes_player_keys[key])

    def _handle_keys_exchanged(self):
        print(self.response.get("msg"))
        list_of_keys = list(self.player.aes_player_keys.keys())
        for key in list_of_keys:
            aes_secret = self.keychain.decrypt(self.player.aes_player_keys[key])
            self.player.aes_player_keys_dec[key] = AESCipher(aes_secret)

        print(self.player.name)
        for secret in self.player.aes_player_keys_dec:
            print("RESULTADO", secret, self.player.aes_player_keys_dec[secret].secret)

        msg = {"action": "finished_setup"}
        return msg

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

    def _handle_randomization_stage(self):
        deck = self.response.get("pseudo_deck")
        new_deck = []

        self.player.randomized_tuple_mapping = {}

        for piece in deck:
            new_cipher = AESCipher()
            ciphertext, nonce, auth_tag = new_cipher.encrypt_aes_gcm(pickle.dumps(piece))
            # If collision exists, generates new key encrypts again
            while ciphertext in self.player.randomized_tuple_mapping.values():
                new_cipher = AESCipher()
                ciphertext, nonce, auth_tag = new_cipher.encrypt_aes_gcm(pickle.dumps(piece))

            self.player.randomized_tuple_mapping[new_cipher.secret] = (ciphertext, nonce, auth_tag)
            new_deck.append(ciphertext)

        random.shuffle(new_deck)

        return {'action': 'next_randomization_step', 'deck': new_deck}

    def _handle_start_selection_stage(self):
        # Picks a piece from the deck or passes, shuffles and sends to another player
        pseudo_deck = self.response.get("deck")
        self.player.npieces = self.response.get("pieces_per_player")

        if random.random() < 0.05:
            random.shuffle(pseudo_deck)
            self.player.encrypted_hand.append(pseudo_deck.pop())
        else:
            random.shuffle(pseudo_deck)

        players_nicks = list(self.player.aes_player_keys_dec.keys())
        player_to_send_deck = random.choice(players_nicks)

        encrypted_message = pickle.dumps({'action': "selection_stage", "deck": pseudo_deck,
                                          'pieces_per_player': self.response.get("pieces_per_player"),
                                          "stock_low": self.response.get("stock_low")})

        encrypted_tuple = self.player.aes_player_keys_dec[player_to_send_deck].encrypt_aes_gcm(encrypted_message)

        msg = {'action': 'send_to_player', 'sender': self.player.name, 'rec': player_to_send_deck,
               'to_send': encrypted_tuple}

        return msg

    def _handle_selection_stage(self):
        # Picks a piece from the deck or passes, shuffles and sends to another player
        pseudo_deck = self.response.get("deck")
        self.player.npieces = self.response.get("pieces_per_player")

        players_nicks = list(self.player.aes_player_keys_dec.keys())

        if len(self.player.encrypted_hand) < self.player.npieces:
            if random.random() < 0.60:
                random.shuffle(pseudo_deck)
                self.player.encrypted_hand.append(pseudo_deck.pop())
            elif random.random() < 0.50:
                # Substitute already selected pieces
                pass
            else:
                random.shuffle(pseudo_deck)

        if len(pseudo_deck) > self.response.get("stock_low"):
            player_to_send_deck = random.choice(players_nicks)

            encrypted_message = pickle.dumps({'action': "selection_stage", "deck": pseudo_deck,
                                              'pieces_per_player': self.response.get("pieces_per_player"),
                                              'stock_low': self.response.get('stock_low')})

            encrypted_tuple = self.player.aes_player_keys_dec[player_to_send_deck].encrypt_aes_gcm(encrypted_message)

            msg = {'action': 'send_to_player', 'sender': self.player.name, 'rec': player_to_send_deck,
                   'to_send': encrypted_tuple}
        else:
            msg = {'action': 'selection_over'}

        return msg

    def _handle_commit_hand(self):
        self.player.hand_commit = HandCommit(self.player.encrypted_hand)

        signed_commit = self.keychain.sign(pickle.dumps(self.player.hand_commit.publishCommit()))

        msg = {"action": 'send_commit', "commit": (self.player.hand_commit.publishCommit(), signed_commit)}

        return msg

    def _handle_validate_selection(self):
        self.player.players_commits = self.response.get("commits")
        print(self.player.player_pub_keys)
        for player in self.player.players_commits:
            if not self.keychain.verify_sign(pickle.dumps(self.player.players_commits[player][0]),
                                             self.player.players_commits[player][1],
                                             readPublicKeyFromPEM(self.player.player_pub_keys[player])):
                print(Colors.BRed + "GAME NOT VALID" + Colors.Color_Off)
                exit(1)

        self.player.pseudo_starting_stock = self.response.get('stock')
        return {"action": "hands_validated"}

    def _handle_secret_message(self):
        cipher = self.player.aes_player_keys_dec[self.response.get('sender')]
        encrypted_tuple = self.response.get('msg')

        deciphered_msg = pickle.loads(cipher.decrypt_aes_gcm(encrypted_tuple))

        return deciphered_msg

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
        score = self.response.get("score")
        if self.response.get("winner") == self.player.name:
            winner = Colors.BRed + "YOU" + Colors.Color_Off
        else:
            winner = Colors.BBlue + winner + Colors.Color_Off
        print(Colors.BGreen + "End GAME, THE WINNER IS: " + winner + "Score:" + str(score))

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
        if action == "secret_message":
            deciphered = self._handle_secret_message()
            action = deciphered.get("action")
            self.response = deciphered
        if action == "login":
            response = self._handle_login()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "you_host":
            self._handle_you_host()
        elif action == "new_player":
            self._handle_new_player()
        elif action == "send_pub_keys":
            print(self.response.get("msg"))
            self.player.player_pub_keys = self.response.get('pub_keys')
        elif action == "key_exchange":
            response = self._handle_key_exchange()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "receiving_aes":
            self._handle_receiving_aes()
        elif action == "keys_exchanged":
            response = self._handle_keys_exchanged()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "waiting_for_host":
            if self.player.host:
                response = self._handle_waiting_for_host_as_host()
                message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                                  self.aes_cipher)
                self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
            else:
                self._handle_waiting_for_host_as_player()
        elif action == "host_start_game":
            response = self._handle_host_start_game()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "randomization_stage":
            response = self._handle_randomization_stage()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "start_selection_stage":
            response = self._handle_start_selection_stage()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "selection_stage":
            response = self._handle_selection_stage()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "commit_hand":
            response = self._handle_commit_hand()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "validate_selection":
            response = self._handle_validate_selection()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "rcv_game_properties":
            response = self._handle_rcv_game_properties()
            if response is not None:
                message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                                  self.aes_cipher)
                self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "end_game":
            self._handle_end_game()
        elif action == "wait":
            self._handle_wait()
        elif action == "disconnect":
            self._handle_disconnect()
