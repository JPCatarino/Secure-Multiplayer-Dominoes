import sys
import selectors
import json
import io
import struct
import os
import random
import time
import pickle

sys.path.append(os.path.abspath(os.path.join('.')))
sys.path.append(os.path.abspath(os.path.join('..')))

import utils.Colors as Colors
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from security.handCommit import verifyHandCommit
from security.asymCiphers import readPublicKeyFromPEM, RSAKeychain
from security.symCiphers import AESCipher
from itertools import combinations
from security.CC_utils import validate_certificates, validateSign
from collections import deque
from security.CC import CitizenCard
from security.selfsignedcerts import generate_selfsigned_cert

# Main socket code from https://realpython.com/python-sockets/

player_messages = {}


class Message:
    def __init__(self, selector, sock, addr, game, player_list, keychain, player_keys_dict, player_keys_dict_PEM, certs,
                 score):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self.game = game
        self.keychain = keychain
        self.player_list = player_list
        self.player_keys_dict = player_keys_dict
        self.player_keys_dict_PEM = player_keys_dict_PEM
        self.certs = certs
        self.player_aes = AESCipher()
        self.cc = CitizenCard()
        self.player_nickname = ""
        self.player_key = None
        self._recv_buffer = b""
        self._send_buffer = b""
        self.request = None
        self.response_created = False
        self._response_sent = False
        self.game_started = False
        self.score = score

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
            # (print("setting write mode"))
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError(f"Invalid events mask mode {repr(mode)}.")
        self.selector.modify(self.sock, events, data=self)

    def _read(self):
        try:
            # Should be ready to read
            data = self.sock.recv(16384)
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
            # print("sending", repr(self._send_buffer), "to", self.addr)
            time.sleep(0.1)
            try:
                # Should be ready to write
                sent = self.sock.send(self._send_buffer)
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]

    def forced_write(self, message):
        # print("sending", message, "to", self.addr)
        time.sleep(0.1)
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
        cert = generate_selfsigned_cert("server", None, self.keychain.keyPair.export_key())
        msg = {"action": "login", "msg": "Welcome to the server, what will be your name?", "server_cert": cert}
        return msg

    def _handle_login(self):

        print("User {} requests login, with nickname {}".format(self.sock.getpeername(), self.request.get("msg")))
        self.player_nickname = self.request.get("msg")
        with open("pseudonyms_used.txt", 'r') as f:
            pseudonyms_used = f.read().splitlines()

        if (self.player_nickname in pseudonyms_used):
            return {"action": "login", "msg": "Welcome to the server, what will be your name?"}

        if (validate_certificates(self.request.get("cert"), self.certs)):
            cert_PEM = self.request.get("cert")
            cert = cryptography.x509.load_pem_x509_certificate(cert_PEM, default_backend())
            cc_pub_key = cert.public_key()
            self.game.cc_pub_keys[self.player_nickname] = cc_pub_key
            print(self.request.get("signature"), self.request.get("data"))
            if (validateSign(self.request.pop("signature"), self.request.pop("data"), cc_pub_key)):
                print("VALID CERT AND SIGNATURE")
        else:
            print("Invalid Certificate! User will not be assigned")
        self.player_keys_dict_PEM[self.request.get("msg")] = self.request.get("pubkey")
        self.player_keys_dict[self.request.get("msg")] = readPublicKeyFromPEM(self.request.get("pubkey"))
        self.player_key = readPublicKeyFromPEM(self.request.get("pubkey"))
        encrypted_secret = self.keychain.encrypt(self.player_aes.secret, self.player_key)
        player_messages[self.player_nickname] = self
        if not self.game.hasHost():  # There is no game for this tabla manager
            self.game.addPlayer(self.request.get("msg"), self.sock, self.game.deck.pieces_per_player)  # Adding host
            msg = {"action": "you_host", "session_key": encrypted_secret, "signed_session_key": self.keychain.sign(encrypted_secret),
                   "msg": Colors.BRed + "You are the host of the game" + Colors.Color_Off}
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
                    msg = {"action": "new_player",
                           "msg": Colors.BYellow + "New Player " + Colors.BGreen + self.request.get("msg")
                                  + Colors.BYellow + " registered in game" + Colors.Color_Off,
                           "nplayers": self.game.nplayers, "game_players": self.game.max_players}
                    print("User " + Colors.BBlue + "{}".format(
                        self.request.get("msg")) + Colors.Color_Off + " joined the game")

                    # send info to all players
                    self.send_all(msg)
                    msg["session_key"] = encrypted_secret
                    msg["signed_session_key"] = self.keychain.sign(encrypted_secret)

                    # check if table is full
                    if self.game.isFull():
                        self.send_to_player(self.player_nickname, msg)
                        print(Colors.BIPurple + "The game is Full" + Colors.Color_Off)
                        sub_player_PEM = {}
                        pair_dict = {}
                        print(Colors.Yellow + "Start Session set-up between clients" + Colors.Color_Off)
                        list_of_keys = self.player_keys_dict_PEM.keys()
                        list_of_pairs = [comb for comb in combinations(list_of_keys, 2)]

                        for pair in list_of_pairs:
                            if pair[0] not in pair_dict.keys():
                                pair_dict[pair[0]] = []
                            pair_dict[pair[0]].append(pair[1])
                        for key in pair_dict:
                            for new_keys in pair_dict[key]:
                                sub_player_PEM[new_keys] = self.player_keys_dict_PEM[new_keys]
                            signed_session_keys = self.keychain.sign(pickle.dumps(sub_player_PEM))
                            msg = {"action": "key_exchange", "session_keys": sub_player_PEM, "signed_session_keys": signed_session_keys,
                                   "msg": Colors.BYellow + "Establishing players secure session...exchanging keys..." + Colors.Color_Off}
                            self.send_to_player(key, msg)
                            sub_player_PEM = {}
                        
                        signed_pub_keys = self.keychain.sign(pickle.dumps(self.player_keys_dict_PEM))
                        msg = {"action": "send_pub_keys",
                               "msg": Colors.BYellow + "Establishing players secure session..." + Colors.Color_Off,
                               "pub_keys": self.player_keys_dict_PEM, "signed_pub_keys": signed_pub_keys}
                        self.send_all(msg)
                    return msg
            else:
                msg = {"action": "disconnect", "msg": "You are already in the game"}
                print("User {} tried to join a game he was already in".format(self.request.get("msg")))
                return msg

    def _handle_aes_exchange(self):
        if "aes_keys" in self.request:
            aes_keys = self.request.get("aes_keys")
            signed_aes_keys = self.request.get("signed_aes_keys")
            list_of_players = aes_keys.keys()
            for player in list_of_players:
                for player_send in aes_keys[player]:
                    print(Colors.Yellow + "Session Set-up between " + self.player_nickname + " and " + player_send,
                          Colors.Color_Off)
                    temp = {}
                    temp_sign = {}
                    temp[player] = aes_keys[player].get(player_send)
                    temp_sign[player] = signed_aes_keys[player].get(player_send)
                    msg = {"action": "receiving_aes", "aes_key": temp, "signed_aes_key": temp_sign, "player_receive": player_send}
                    self.send_all(msg)
        msg = {"action": "keys_exchanged",
               "msg": Colors.BYellow + "Keys have been exchanged!" + Colors.Color_Off}
        self.send_all(msg)
        return msg

    def _handle_finish_setup(self):
        print(Colors.Red, "Waiting for host to start game", Colors.Color_Off)
        msg = {"action": "waiting_for_host",
               "msg": Colors.BRed + "Waiting for host to start the game" + Colors.Color_Off}
        return msg

    def _handle_start_game(self):
        self.game.deck.generate_pseudonymized_deck()
        self.game.randomization_list = list(player_messages.keys())
        self.game.randomization_order = list()

        print(Colors.Green, "Pseudonymized Deck Generated", Colors.Color_Off)
        print(self.game.deck.pseudo_deck)

        print(Colors.BGreen, "Starting Randomization Stage", Colors.Color_Off)
        print(Colors.BGreen, "Next in order ->", self.game.randomization_list[-1], Colors.Color_Off)

        msg_one = {"action": "randomization_stage",
                   "pseudo_deck": self.game.deck.pseudo_deck}
        msg_two = {"action": "wait", "msg": Colors.BYellow + "Randomization Stage will Begin" + Colors.Color_Off}
        # self.game.players_ready = True
        self.send_all(msg_two)
        self.game.randomization_order.append(self.game.randomization_list[-1])
        self.send_to_player(self.game.randomization_list.pop(), msg_one)
        return msg_two

    def _handle_next_randomization_step(self):
        self.game.deck.pseudo_deck = self.request.get("deck")

        if len(self.game.randomization_list) != 0:
            print(Colors.BGreen, "Next Randomization step", Colors.Color_Off)
            print(Colors.BGreen, "Next in order ->", self.game.randomization_list[-1], Colors.Color_Off)

            msg_one = {"action": "randomization_stage",
                       "pseudo_deck": self.game.deck.pseudo_deck}

            msg_two = {"action": "wait",
                       "msg": Colors.BYellow + "Randomization Stage is in progress" + Colors.Color_Off}

            self.game.randomization_order.append(self.game.randomization_list[-1])
            self.send_all(msg_two)
            self.send_to_player(self.game.randomization_list.pop(), msg_one)
            return msg_two
        else:
            # If randomization ended, skip to next stage
            print(Colors.BGreen, "Randomization Ended, Starting Selection", Colors.Color_Off)
            msg_one = {"action": "start_selection_stage", "deck": self.game.deck.pseudo_deck,
                       "pieces_per_player": self.game.deck.pieces_per_player,
                       "stock_low": len(self.game.deck.pseudo_deck) - (
                               self.game.nplayers * self.game.deck.pieces_per_player), "padding": []}
            msg_two = {"action": "wait", "msg": Colors.BYellow + "Selection stage will start" + Colors.Color_Off}

            self.send_all(msg_two)
            players_to_send = list(player_messages.keys())
            random.shuffle(players_to_send)
            self.send_to_player(players_to_send.pop(), msg_one)
            return msg_two

    def _handle_selection_stage_over(self):
        print(Colors.Yellow + "Selection stage is over! Requesting hand commits!" + Colors.Color_Off)
        self.game.deck.init_stock = self.request.get("deck")
        msg = {'action': 'commit_hand'}
        self.send_all(msg)
        return msg

    def _handle_send_commit(self):
        print(Colors.Green, self.player_nickname, "sent his hand commit!", Colors.Color_Off)
        self.game.players_commits[self.player_nickname] = self.request.get("commit")

        for player in self.game.players_commits:
            if not self.keychain.verify_sign(pickle.dumps(self.game.players_commits[player][0]),
                                             self.game.players_commits[player][1],
                                             self.player_keys_dict[player]):
                print(Colors.BRed + "GAME NOT VALID" + Colors.Color_Off)
                exit(1)

        if len(self.game.players_commits) < self.game.nplayers:
            return {'action': "wait", 'msg': Colors.BYellow + "Commits in progress" + Colors.Color_Off}
        else:
            print(Colors.Green, "All hands commitments received!", Colors.Color_Off)
            msg = {'action': "validate_selection", "commits": self.game.players_commits,
                   "stock": self.game.deck.init_stock}
            self.send_all(msg)
            return msg

    def _handle_hands_validated(self):
        print(Colors.Green + "Player " + self.player_nickname + " validated game start" + Colors.Color_Off)
        self.game.init_validation_count += 1

        if self.game.init_validation_count < self.game.nplayers:
            return {"action": "wait", "msg": "Await further validation"}
        else:
            for player in self.game.players:
                player.updatePieces(self.game.deck.pieces_per_player)
            msg_one = {"action": "reveal_keys", 'msg': Colors.BYellow + "Revealing your keys" + Colors.Color_Off}
            msg_two = {"action": "wait", 'msg': Colors.BYellow + "Revelation in Progress" + Colors.Color_Off}
            self.game.randomization_order = deque(self.game.randomization_order)
            self.game.first_in_randomization = self.game.randomization_order[-1]
            self.send_to_player(self.game.randomization_order[-1], msg_one)
            self.send_all(msg_two)
            return msg_two

    def _handle_revealed_keys(self):
        print(Colors.Yellow, "Sending keys to reveal!", Colors.Color_Off)
        msg = {"action": "keys_to_reveal", "keys_dict": self.request.get("keys_dict")}
        self.send_all(msg)
        return {"action": "keys_sent", "msg": "Keys were sent"}

    def _handle_revealed_key_for_piece(self):
        self.game.randomization_order.rotate(1)
        more = False
        if self.game.randomization_order[-1] != self.game.first_in_randomization:
            print("Next in randomization order -> ", self.game.randomization_order[-1])
            more = True

        msg = {"action": "piece_key_to_reveal", "key_dict": self.request.get("key_dict"), "more": more}
        self.send_to_player(self.game.currentPlayer().name, msg)
        self.game.randomization_order[-1]
        return {"action": "wait", "msg": "Keys were sent"}

    def _handle_waiting_for_keys(self):
        self.game.players_waiting += 1
        if self.game.players_waiting >= self.game.nplayers:
            self.game.randomization_order.rotate(1)
            self.game.players_waiting = 0
            if self.game.first_in_randomization != self.game.randomization_order[-1]:
                print(Colors.Green, "Revelation is afoot!", Colors.Color_Off)
                msg_one = {"action": "reveal_keys", 'msg': Colors.BYellow + "Revealing your keys" + Colors.Color_Off}
                msg_two = {"action": "wait", 'msg': Colors.BYellow + "Revelation in Progress" + Colors.Color_Off}
                self.game.randomization_order = deque(self.game.randomization_order)
                print("Next in randomization order -> ", self.game.randomization_order[-1])
                self.send_to_player(self.game.randomization_order[-1], msg_one)
                self.send_all(msg_two)
                return msg_two
            else:
                self.game.players_waiting = 0
                print(Colors.BGreen + "Revelation Stage End! Preparing for tile de-anonymization" + Colors.Color_Off)
                padding = []
                pub_key_list = []
                dummy_key = RSAKeychain(2048)
                # Create padding for the messages to keep size
                for i in range(0, (self.game.nplayers * self.game.deck.pieces_per_player)):
                    padding.append(os.urandom(sys.getsizeof(dummy_key.exportPubKey())))
                for i in range(0, len(self.game.deck.pseudo_deck)):
                    pub_key_list.append(None)
                    padding.insert(0, None)

                msg_one = {"action": "start_deanon_stage", "pub_key_list": pub_key_list,
                           "pieces_per_player": self.game.deck.pieces_per_player,
                           "max_pieces": (self.game.nplayers * self.game.deck.pieces_per_player), "padding": padding}

                msg_two = {"action": "wait",
                           "msg": Colors.BYellow + "Tile De-anonymization stage will start!" + Colors.Color_Off}

                self.send_all(msg_two)
                players_to_send = list(player_messages.keys())
                random.shuffle(players_to_send)
                self.send_to_player(players_to_send.pop(), msg_one)
                return msg_two
                return self._handle_ready_to_play()
        else:
            return {'action': 'wait', 'msg': Colors.BYellow + "Waiting for other players to reveal" + Colors.Color_Off}

    def _handle_deanon_prep_over(self):
        print(Colors.Green + "Translating anonymous tiles" + Colors.Color_Off)
        pub_key_list = self.request.get("pub_key_list")
        msg_list = []

        for i in range(0, len(self.game.deck.deck)):
            msg_list.append(None)

        for key in pub_key_list:
            if key is not None:
                tile_index = pub_key_list.index(key)
                tile_to_encrypt = self.game.deck.deck[tile_index]
                self.game.pieces_translated.append(tile_to_encrypt)
                key_to_encrypt = self.game.deck.pseudo_table[tile_index]
                msg_to_encrypt = pickle.dumps((tile_to_encrypt, key_to_encrypt))
                ciphertext = self.keychain.encrypt(msg_to_encrypt, readPublicKeyFromPEM(key))
                msg_list[tile_index] = ciphertext

        msg = {"action": "decipher_tiles", "ciphered_tiles": msg_list}
        self.send_all(msg)
        return msg

    def _handle_request_piece_deanon(self, c_player):
        print(Colors.Green + "Translating anonymous tile" + Colors.Color_Off)

        tile_index, tile = self.request.get("piece")

        tile_to_encrypt = self.game.deck.deck[tile_index]
        self.game.pieces_translated.append(tile_to_encrypt)
        key_to_encrypt = self.game.deck.pseudo_table[tile_index]
        msg_to_encrypt = pickle.dumps((tile_to_encrypt, key_to_encrypt))
        msg_to_send = {"action": "insert_in_hand", "new_tile": msg_to_encrypt}

        ciphered_message = self.player_aes.encrypt_aes_gcm(pickle.dumps(msg_to_send))

        return {"action": "secret_message", "sender": "server", "msg": ciphered_message}

    def _handle_send_to_player(self):
        msg_to_send = {'action': 'secret_message', 'sender': self.request.get('sender'),
                       'msg': self.request.get('to_send')}
        print(Colors.Yellow, "Redirecting message from", self.request.get('sender'), "to", self.request.get("rec"),
              Colors.Color_Off)
        self.send_to_player(self.request.get('rec'), msg_to_send)
        return {"action": 'wait', 'msg': Colors.BGreen + "Message sent" + Colors.Color_Off}

    def _handle_ready_to_play(self):
        self.game.players_waiting += 1
        self.game.players_played_pieces[self.player_nickname] = []

        if self.game.players_waiting >= self.game.nplayers:
            self.game.players_waiting = 0
            self.game.started = True
            self.game.next_action = "play"

            msg = {"action": "host_start_game",
                   "msg": Colors.BYellow + "The Host started the game" + Colors.Color_Off}
            self.send_all(msg)
            return msg
        else:
            return {"action": "wait", "msg": Colors.Yellow + "Wait for other players" + Colors.Color_Off}

    def _handle_get_game_properties(self):
        self.game.players_ready = True
        msg = {"action": "rcv_game_properties"}
        msg.update(self.game.toJson())
        return msg

    def _handle_request_piece_reveal(self, player):
        print(Colors.Yellow, self.player_nickname, "Piece Reveal in Progress", Colors.Color_Off)
        if self.game.randomization_order[-1] == self.game.first_in_randomization:
            player.updatePieces(1)
            self.game.deck.init_stock = self.request.get("new_stock")

        msg_one = {"action": "reveal_piece_key", "new_piece": self.request.get('new_piece'),
                   'new_stock': self.request.get("new_stock"), 'key_dict': {},
                   'msg': Colors.BYellow + "Revealing your key" + Colors.Color_Off}
        msg_two = {"action": "wait", 'msg': Colors.BYellow + "Player" + self.player_nickname +
                                            " has requested a piece. Revelation in Progress" + Colors.Color_Off}
        self.send_to_player(self.game.randomization_order[-1], msg_one)
        self.send_all(msg_two)
        return msg_two

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
        self.game.GameEnded = self.request.get("win")
        if self.request.get("piece") is not None:
            signed_piece = self.request.get("signed_piece")
            print(Colors.Yellow + "Validating Play Signature..." + Colors.Color_Off)

            if not self.keychain.verify_sign(pickle.dumps(self.request.get("piece")), signed_piece, self.player_key):
                self.send_all({"action": "wait", "msg": Colors.BRed + "Player" + self.player_nickname +
                                                        "sent an invalid signature!" + Colors.Color_Off})
                exit(-1)

            print(Colors.Green + "Play Signature validated!" + Colors.Color_Off)

            print(Colors.Yellow + "Checking if player has played this piece before" + Colors.Color_Off)
            if self.request.get("piece") in self.game.players_played_pieces[self.player_nickname]:
                print(Colors.Red + self.player_nickname + " is playing duplicate pieces! He is a cheater!"
                      + Colors.Color_Off)
                msg = {"action": "disconnect",
                       "msg": Colors.Red + self.player_nickname + " is playing duplicate pieces! He is a cheater!"
                              + Colors.Color_Off}
                self.send_all(msg)
                return msg

            self.game.players_played_pieces[self.player_nickname].append(self.request.get("piece"))

            print(Colors.Yellow + "Checking if piece has been translated once" + Colors.Color_Off)
            if self.request.get("piece") not in self.game.pieces_translated:
                print(Colors.Red + "I think this player is a cheater. Going to check!" + Colors.Color_Off)
                self.game.players_ready = False
                msg = {"action": "reveal_everything", "next_act": "validate_protest"}
                msg.update({"signed_action": self.keychain.sign(pickle.dumps(msg.get("action")))})
                self.send_all(msg)
                return msg

            print(Colors.Green + "This piece seems to be clear. Going forward." + Colors.Color_Off)

            last_table = self.game.deck.in_table.copy()

            player.nopiece = False
            player.updatePieces(-1)
            if self.request.get("edge") == 0:
                self.game.deck.in_table.insert(0, self.request.get("piece"))
            else:
                self.game.deck.in_table.insert(len(self.game.deck.in_table), self.request.get("piece"))

        print("player pieces ", player.num_pieces)
        print("player " + player.name + " played " + str(self.request.get("piece")))
        print("in table -> " + ' '.join(map(str, self.game.deck.in_table)) + "\n")

        if "signed_piece" in self.request:
            msg = {"action": "validate_this_play"}
            msg.update({"last_piece": self.request.get("piece")})
            msg.update({"last_player": self.player_nickname})
            msg.update({"signed_piece": self.request.get("signed_piece")})
            msg.update({"last_table": last_table})
        else:
            msg = {"action": "rcv_game_properties"}

        msg.update(self.game.toJson())
        self.send_all(msg)
        return msg

    def _handle_play_piece_epilogue(self, player):
        self.game.players_waiting += 1

        if "player_cheated" in self.request:
            print(Colors.Yellow, "Checking if player cheating confirmation message was compromised", Colors.Color_Off)
            if not self.keychain.verify_sign(pickle.dumps(self.request.get("player_cheated")), self.request.get("signed_player_cheated"), self.player_keys_dict[self.player_nickname]):
                print(Colors.Red, "Player cheating confirmation has been compromised. Shutting Down!", Colors.Color_Off)
                exit(-1)
            print(Colors.BGreen, "Player cheating confirmation integrity not compromised", Colors.Color_Off)
        
        if self.request.get("player_cheated"):
            self.game.player_cheated = True

        if self.game.players_waiting >= self.game.nplayers:
            self.game.players_waiting = 0
            if self.game.player_cheated:
                self.game.players_ready = False
                print(Colors.Red + "There has been a protest. Going to check if player cheated!" + Colors.Color_Off)
                msg = {"action": "reveal_everything", "next_act": "validate_protest"}
                msg.update({"signed_action": self.keychain.sign(pickle.dumps(msg.get("action")))})
            else:
                if self.game.GameEnded:
                    if player.checkifWin():
                        self.game.players_ready = False
                        print(Colors.BGreen + " WINNER " + player.name + Colors.Color_Off)
                        self.game.game_winner = player.name
                        msg = {"action": "reveal_everything", "next_act": "validate_game"}
                        msg.update({"signed_action": self.keychain.sign(pickle.dumps(msg.get("action")))})
                else:
                    self.game.nextPlayer()
                    msg = {"action": "rcv_game_properties"}
        else:
            return {"action": "wait", "msg": Colors.Yellow + "Wait for other players" + Colors.Color_Off}

        msg.update(self.game.toJson())
        self.send_all(msg)
        return msg

    def _handle_pass_play(self, player):
        self.game.nextPlayer()
        # If all players passed
        if all([player.nopiece for player in self.game.players]):
            self.game.players_ready = False
            print("No piece END")
            self.game.game_winner = "TIE"
            msg = {"action": "reveal_everything", "next_act": "validate_game"}
            msg.update({"signed_action": self.keychain.sign(pickle.dumps(msg.get("action")))})
            msg.update(self.game.toJson())
        # Update the variable nopiece so that the server can know if the player has passed the previous move
        else:
            print("No piece")
            player.nopiece = True
            msg = {"action": "rcv_game_properties"}
            msg.update(self.game.toJson())

        self.send_all(msg)
        return msg

    def _handle_validate_game(self):
        signed_msg = self.request.pop("signed_msg", None)

        print(Colors.Yellow, "Checking if Validate Game message from", self.player_nickname ,"was compromised", Colors.Color_Off)
        if not self.keychain.verify_sign(pickle.dumps(self.request), signed_msg, self.player_keys_dict[self.player_nickname]):
                print(Colors.Red, "Validate Game action has been compromised. Shutting Down!", Colors.Color_Off)
                exit(-1)
        print(Colors.BGreen, "Validate Game action integrity not compromised", Colors.Color_Off)
        self.game.players_waiting += 1
        self.game.players_commits_confirmations[self.player_nickname] = self.request.get("hand_commit_confirmation")
        self.game.deck.tile_keys_per_player[self.player_nickname] = self.request.get("tile_keys")
        self.game.player_initial_hands[self.player_nickname] = []
        self.game.players_collected_key[self.player_nickname] = self.request.get("collected_keys")
        self.game.players_remaining_hands[self.player_nickname] = self.request.get("remaining_hand")

        if self.game.players_waiting >= self.game.nplayers:
            self.game.players_waiting = 0

            # Verify all hand commitments to check if player cheated in providing information
            for player_name in self.game.players_commits:

                if not verifyHandCommit(self.game.players_commits[player_name][0],
                                        self.game.players_commits_confirmations[player_name]):
                    print(Colors.Red + player_name + " Sent an Invalid Hand Commit" + Colors.Color_Off)
                    print(Colors.Red + player_name + " is a cheater!" + Colors.Color_Off)
                    msg = {"action": "disconnect",
                           "msg": Colors.Red + player_name + " is a cheater!" + Colors.Color_Off}
                    self.send_all(msg)
                    return msg
                else:
                    print(Colors.Green + player_name + " Sent a valid Hand Commit" + Colors.Color_Off)

            # Decrypt all tiles in hand commit
            for player_name in self.game.players_commits_confirmations:
                player_encrypted_tiles = self.game.players_commits_confirmations[player_name][1]

                for tile in player_encrypted_tiles:
                    tile_to_decrypt = tile
                    while True:
                        current_player_key = self.game.randomization_order[-1]
                        current_key_pairs = self.game.deck.tile_keys_per_player[current_player_key]

                        key_tuple_dict = {}

                        key_to_use = [keys for keys in current_key_pairs.keys() if
                                      current_key_pairs[keys][0] in tile_to_decrypt]

                        for key in key_to_use:
                            key_tuple_dict[current_key_pairs[key]] = key

                        for tuple_piece in key_tuple_dict:
                            if tile_to_decrypt == tuple_piece[0]:
                                decipher = AESCipher(key_tuple_dict[tuple_piece])
                                deciphered_piece = pickle.loads(decipher.decrypt_aes_gcm(tuple_piece))

                        tile_to_decrypt = deciphered_piece
                        self.game.randomization_order.rotate(1)

                        if self.game.randomization_order[-1] == self.game.first_in_randomization:
                            tile_index, tile = tile_to_decrypt
                            translated_tiles = self.game.deck.deck[tile_index]
                            self.game.player_initial_hands[player_name].append(translated_tiles)
                            break

            for player_name in self.game.player_initial_hands:
                player_played_pieces = self.game.players_played_pieces[player_name]
                player_pieces_owned = player_played_pieces + self.game.players_remaining_hands[player_name]
                for tile in player_pieces_owned:
                    if tile not in self.game.player_initial_hands[player_name]:
                        print(Colors.Red + player_name + " owns a piece not in his initial hand" + Colors.Color_Off)
                        print(Colors.Yellow + " Checking if player has the keys to" + str(tile) + Colors.Color_Off)
                        key_tuples = [key_tuple for key_tuple in
                                      list(self.game.players_collected_key[player_name].keys()) if
                                      type(key_tuple) == tuple]
                        if not key_tuples:
                            print(Colors.Red, player_name, "has no keys", Colors.Color_Off)
                            print(Colors.Red + player_name + " is a cheater!" + Colors.Color_Off)
                            msg = {"action": "disconnect",
                                   "msg": Colors.Red + player_name + " is a cheater!" + Colors.Color_Off}
                            self.send_all(msg)
                            return msg

                        player_has_piece = False
                        for d_tuple in key_tuples:
                            tuple_to_check = list(self.game.players_collected_key[player_name][d_tuple].keys())[-1]
                            key = self.game.players_collected_key[player_name][d_tuple][tuple_to_check]
                            decipher = AESCipher(key)
                            anon_tile_to_check = pickle.loads(decipher.decrypt_aes_gcm(tuple_to_check))
                            tile_to_check = self.game.deck.deck[anon_tile_to_check[0]]

                            if tile_to_check == tile:
                                player_has_piece = True
                                break

                        if not player_has_piece:
                            print(Colors.Red, player_name, "doesn't have ", tile, "keys", Colors.Color_Off)
                            print(Colors.Red + player_name + " is a cheater!" + Colors.Color_Off)
                            msg = {"action": "disconnect"}
                            self.send_all(msg)
                            return msg
                        print(Colors.Green, player_name, "has ", tile, "keys", Colors.Color_Off)

                print(Colors.Green + player_name + " played only valid tiles" + Colors.Color_Off)

            print(Colors.Green + "Everything Valid, proceeding to score" + Colors.Color_Off)
            msg = {"action": "report_score", "winner": self.game.game_winner,
                   "remaining_hands": self.game.players_remaining_hands,
                   "hand_commits_confirmation": self.game.players_commits_confirmations}
            msg.update({"signed_msg": self.keychain.sign(pickle.dumps(msg))})
            self.send_all(msg)
            return msg

        else:
            return {"action": "wait", "msg": Colors.Green + "Wait for another players" + Colors.Color_Off}

    def _handle_validate_protest(self):
        signed_msg = self.request.pop("signed_msg", None)

        print(Colors.Yellow, "Checking if Validate Protest message from", self.player_nickname ,"was compromised", Colors.Color_Off)
        if not self.keychain.verify_sign(pickle.dumps(self.request), signed_msg, self.player_keys_dict[self.player_nickname]):
                print(Colors.Red, "Validate protest action has been compromised. Shutting Down!", Colors.Color_Off)
                exit(-1)
        print(Colors.BGreen, "Validate protest action integrity not compromised", Colors.Color_Off)
        self.game.players_waiting += 1
        self.game.players_commits_confirmations[self.player_nickname] = self.request.get("hand_commit_confirmation")
        self.game.deck.tile_keys_per_player[self.player_nickname] = self.request.get("tile_keys")
        self.game.player_initial_hands[self.player_nickname] = []
        self.game.players_collected_key[self.player_nickname] = self.request.get("collected_keys")
        self.game.players_remaining_hands[self.player_nickname] = self.request.get("remaining_hand")

        if self.game.players_waiting >= self.game.nplayers:
            self.game.players_waiting = 0

            cheater_name = self.game.currentPlayer().name

            print(Colors.Yellow, "Checking if", cheater_name, "cheated!", Colors.Color_Off)

            if not verifyHandCommit(self.game.players_commits[cheater_name][0],
                                    self.game.players_commits_confirmations[cheater_name]):
                print(Colors.Red + cheater_name + " Sent an Invalid Hand Commit" + Colors.Color_Off)
                print(Colors.Red + cheater_name + " is a cheater!" + Colors.Color_Off)
                msg = {"action": "disconnect",
                       "msg": Colors.Red + cheater_name + " is a cheater! GAME ENDED" + Colors.Color_Off}
                self.send_all(msg)
                return msg
            else:
                print(Colors.Green + cheater_name + " Sent a valid Hand Commit" + Colors.Color_Off)

            # Decrypt all tiles in hand commit
            player_encrypted_tiles = self.game.players_commits_confirmations[cheater_name][1]

            for tile in player_encrypted_tiles:
                tile_to_decrypt = tile
                while True:
                    current_player_key = self.game.randomization_order[-1]
                    current_key_pairs = self.game.deck.tile_keys_per_player[current_player_key]

                    key_tuple_dict = {}

                    key_to_use = [keys for keys in current_key_pairs.keys() if
                                  current_key_pairs[keys][0] in tile_to_decrypt]

                    for key in key_to_use:
                        key_tuple_dict[current_key_pairs[key]] = key

                    for tuple_piece in key_tuple_dict:
                        if tile_to_decrypt == tuple_piece[0]:
                            decipher = AESCipher(key_tuple_dict[tuple_piece])
                            deciphered_piece = pickle.loads(decipher.decrypt_aes_gcm(tuple_piece))

                    tile_to_decrypt = deciphered_piece
                    self.game.randomization_order.rotate(1)

                    if self.game.randomization_order[-1] == self.game.first_in_randomization:
                        tile_index, tile = tile_to_decrypt
                        translated_tiles = self.game.deck.deck[tile_index]
                        self.game.player_initial_hands[cheater_name].append(translated_tiles)
                        break

            player_played_pieces = self.game.players_played_pieces[cheater_name]
            player_pieces_owned = player_played_pieces + self.game.players_remaining_hands[cheater_name]
            for tile in player_pieces_owned:
                if tile not in self.game.player_initial_hands[cheater_name]:
                    print(Colors.Red + cheater_name + " owns a piece not in his initial hand" + Colors.Color_Off)
                    print(Colors.Yellow + " Checking if player has the keys to" + str(tile) + Colors.Color_Off)
                    key_tuples = [key_tuple for key_tuple in
                                  list(self.game.players_collected_key[cheater_name].keys()) if
                                  type(key_tuple) == tuple]
                    if not key_tuples:
                        print(Colors.Red, cheater_name, "has no keys", Colors.Color_Off)
                        print(Colors.Red + cheater_name + " is a cheater!" + Colors.Color_Off)
                        msg = {"action": "disconnect",
                               "msg": Colors.Red + cheater_name + " is a cheater! GAME ENDED" + Colors.Color_Off}
                        self.send_all(msg)
                        return msg

                    player_has_piece = False
                    for d_tuple in key_tuples:
                        tuple_to_check = list(self.game.players_collected_key[cheater_name][d_tuple].keys())[-1]
                        key = self.game.players_collected_key[cheater_name][d_tuple][tuple_to_check]
                        decipher = AESCipher(key)
                        anon_tile_to_check = pickle.loads(decipher.decrypt_aes_gcm(tuple_to_check))
                        tile_to_check = self.game.deck.deck[anon_tile_to_check[0]]

                        if tile_to_check == tile:
                            player_has_piece = True
                            break

                    if not player_has_piece:
                        print(Colors.Red, cheater_name, "doesn't have ", tile, "keys", Colors.Color_Off)
                        print(Colors.Red + cheater_name + " is a cheater!" + Colors.Color_Off)
                        msg = {"action": "disconnect",
                               "msg": Colors.Red + cheater_name + " is a cheater! GAME ENDED" + Colors.Color_Off}
                        self.send_all(msg)
                        return msg
                    print(Colors.Green, cheater_name, "has ", tile, "keys", Colors.Color_Off)

            print(Colors.Green + cheater_name + " played only valid tiles" + Colors.Color_Off)

            print(Colors.Green + "Player" + cheater_name + "didn't cheat!" + Colors.Color_Off)

            msg = {"action": "disconnect",
                   "msg": Colors.Red + " Cheating protest ocurred! GAME ENDED" + Colors.Color_Off}
            self.send_all(msg)
            return msg
        else:
            return {"action": "wait", "msg": Colors.Yellow + "Wait for other players" + Colors.Color_Off}

    def _handle_score_report(self):
        signed_msg = self.request.pop("signed_msg", None)

        print(Colors.Yellow, "Checking if score report message from", self.player_nickname ,"was compromised", Colors.Color_Off)
        if not self.keychain.verify_sign(pickle.dumps(self.request), signed_msg, self.player_keys_dict[self.player_nickname]):
                print(Colors.Red, "Score Report has been compromised. Shutting Down!", Colors.Color_Off)
                exit(-1)
        print(Colors.BGreen, "Score Report action integrity not compromised", Colors.Color_Off)
        self.game.players_waiting += 1
        self.game.players_calculated_scores[self.player_nickname] = self.request.get("score")
        self.game.players_possible_winner[self.player_nickname] = self.request.get("possible_winner")

        if self.game.players_waiting >= self.game.nplayers:
            self.game.players_waiting = 0
            score_history = {}
            score = 0
            self.game.score = 0

            if self.game.game_winner == "TIE":
                winner = None
                for player_name in self.game.players_remaining_hands:
                    score = 0
                    for piece in self.game.players_remaining_hands[player_name]:
                        score += piece.values[0].value + piece.values[1].value
                    score_history[player_name] = score
                for player in score_history:
                    if winner is None:
                        winner = player
                    elif score_history[winner] > score_history[player]:
                        winner = player
                for player_name in score_history:
                    if player_name != winner:
                        self.game.score += score_history[player_name]
            else:
                self.game.score = 0
                winner = self.game.game_winner
                for player_name in self.game.players_remaining_hands:
                    if player_name != winner:
                        for piece in self.game.players_remaining_hands[player_name]:
                            self.game.score += piece.values[0].value + piece.values[1].value

            print(Colors.Green, "I expect the winner to be ", winner, Colors.Color_Off)
            print(Colors.Green, "I expect the score to be ", self.game.score, Colors.Color_Off)
            print(Colors.Yellow, "Checking if players agree with winner", Colors.Color_Off)
            for possible_winner in self.game.players_possible_winner.values():
                if possible_winner != winner:
                    print(Colors.Red, "There's disagreement over the winner. Closing game!", Colors.Color_Off)
                    exit(-1)
            print(Colors.Green, "There's agreement over the winner!", Colors.Color_Off)

            print(Colors.Yellow, "Checking if players agree with score", Colors.Color_Off)
            for expected_score in self.game.players_calculated_scores.values():
                if expected_score != self.game.score:
                    print(Colors.Red, "There's disagreement over the score! Closing game.", Colors.Color_Off)
                    exit(-1)
            print(Colors.Green, "There's agreement over the score!", Colors.Color_Off)

            msg = {"action": "end_game", "winner": winner, "score": self.game.score}
            msg.update({"signed_msg": self.keychain.sign(pickle.dumps(msg))})
            self.send_all(msg)
            return msg
        else:
            return {"action": "wait", "msg": Colors.Yellow + "Wait for other players" + Colors.Color_Off}

    def _handle_assign_score(self):
        if self.request.get("signed_score"):
            score_sig = self.request.get("signed_score")
            data = self.request.get("data")

            if self.request.get("player") in self.game.cc_pub_keys.keys():
                pub_key = self.game.cc_pub_keys[self.request.get("player")]
                print(Colors.Green, "Player is valid. Points will be attributed", Colors.Color_Off)
            else:
                print(Colors.Red, "Player didn't have a valid certificate. No points will be attributed",
                      Colors.Color_Off)
                return {"action": "wait", "msg": Colors.Yellow + "Game Ended" + Colors.Color_Off}

            if (validateSign(score_sig, data, pub_key)):
                content = self.request.get("player") + " - " + str(self.game.score) + "\n"
                f = open("scoreboard.txt", "a")
                f_names = open("pseudonyms_used.txt", "a")
                names_content = self.request.get("player") + "\n"
                f.write(content)
                f_names.write(names_content)
                f.close()
                f_names.close()
        return {"action": "wait", "msg": Colors.Yellow + "Game Ended" + Colors.Color_Off}

    def _create_response_json_content(self):
        # ADD HERE MORE MESSSAGES
        # print(self.request)
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
        elif action == "next_randomization_step":
            content = self._handle_next_randomization_step()
            self._set_selector_events_mask("r")
        elif action == "selection_over":
            content = self._handle_selection_stage_over()
            self._set_selector_events_mask("r")
        elif action == "send_commit":
            content = self._handle_send_commit()
            self._set_selector_events_mask("r")
        elif action == "hands_validated":
            content = self._handle_hands_validated()
            self._set_selector_events_mask("r")
        elif action == "revealed_keys":
            content = self._handle_revealed_keys()
            self._set_selector_events_mask("r")
        elif action == "waiting_for_keys":
            content = self._handle_waiting_for_keys()
            self._set_selector_events_mask("r")
        elif action == "deanon_prep_over":
            content = self._handle_deanon_prep_over()
            self._set_selector_events_mask("r")
        elif action == "ready_to_play":
            content = self._handle_ready_to_play()
            self._set_selector_events_mask("r")
        elif action == "get_game_properties":
            content = self._handle_get_game_properties()
            self._set_selector_events_mask("r")
        elif action == "send_to_player":
            content = self._handle_send_to_player()
            self._set_selector_events_mask("r")
        elif action == "validate_game":
            content = self._handle_validate_game()
            self._set_selector_events_mask("r")
        elif action == "validate_protest":
            content = self._handle_validate_protest()
            self._set_selector_events_mask("r")
        elif action == "score_report":
            content = self._handle_score_report()
            self._set_selector_events_mask("r")
        elif action == "assign_score":
            content = self._handle_assign_score()
            self._set_selector_events_mask("r")
        else:
            content = {"action": "wait", "msg": f'Error: invalid action "{action}".'}
        if self.game.isFull() & self.game.players_ready:
            c_player = self.game.currentPlayer()
            if self.sock == c_player.socket:
                if action == "get_piece":
                    content = self._handle_get_piece(c_player)
                    self._set_selector_events_mask("r")
                elif action == "request_piece_reveal":
                    content = self._handle_request_piece_reveal(c_player)
                    self._set_selector_events_mask("r")
                elif action == "request_piece_deanon":
                    content = self._handle_request_piece_deanon(c_player)
                    self._set_selector_events_mask("r")
                elif action == "play_piece":
                    content = self._handle_play_piece(c_player)
                    self._set_selector_events_mask("r")
                elif action == "pass_play":
                    content = self._handle_pass_play(c_player)
                    self._set_selector_events_mask("r")
            else:
                content = {"action": "wait", "msg": Colors.BRed + "Not Your Turn" + Colors.Color_Off}

            if action == "revealed_key_for_piece":
                content = self._handle_revealed_key_for_piece()
                self._set_selector_events_mask("r")
            elif action == "play_piece_ep":
                content = self._handle_play_piece_epilogue(self.game.currentPlayer())
                self._set_selector_events_mask("r")

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
        player_messages[player_name].forced_write(msg)
        time.sleep(0.2)
