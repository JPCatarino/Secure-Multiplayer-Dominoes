import sys, os
import selectors
import json
import io
import struct
import string
import random
import pickle
from functools import reduce

sys.path.append(os.path.abspath(os.path.join('.')))
sys.path.append(os.path.abspath(os.path.join('..')))

from dominoes.deck_utils import Player
from utils import Colors as Colors
from security.symCiphers import AESCipher
from security.asymCiphers import readPublicKeyFromPEM, RSAKeychain
from security.handCommit import *
from security.hashFunctions import *


# Main socket code from https://realpython.com/python-sockets/

class Message:
    def __init__(self, selector, sock, addr, request, player, keychain, player_cc, aes_cipher=None, cheater=None):
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
        self.cheater = cheater

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
        #print("received response", repr(self.response), "from", self.addr)
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
            #print("sending", repr(self._send_buffer), "to", self.addr)
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
        signature, data = self.cc.signData(nickname)
        cert = self.cc.get_signature_cert()
        # cc_pubKey = self.cc.get_pubKey()
        print(Colors.BYellow + "Your name is " + Colors.BBlue + nickname + Colors.Color_Off)
        msg = {"action": "req_login", "pubkey": self.keychain.exportPubKey(), "msg": nickname,
               "signature": signature, "cert": cert, "data": data}
        self.player = Player(nickname, self.sock, self.cheater)
        return msg

    def _handle_you_host(self):
        aes_secret = self.keychain.decrypt(self.response.get("session_key"))
        self.aes_cipher = AESCipher(aes_secret)
        print("Session", aes_secret)
        self.player.server_aes_cipher = AESCipher(aes_secret)
        self.player.host = True
        print(Colors.Blue + "Player " + self.player.name + "is hosting the game!" + Colors.Color_Off)

    def _handle_new_player(self):
        if "session_key" in self.response:
            aes_secret = self.keychain.decrypt(self.response.get("session_key"))
            print("Session", aes_secret)
            self.aes_cipher = AESCipher(aes_secret)
            self.player.server_aes_cipher = AESCipher(aes_secret)
        print(self.response.get("msg"))
        print("There are " + str(self.response.get("nplayers")) + "\\" + str(self.response.get("game_players")))
        self.player.nplayers = self.response.get("nplayers")

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

        if len(
                self.player.aes_player_keys_dec) >= self.player.nplayers - 1 and not self.player.already_have_player_keys:
            msg = {"action": "finished_setup"}
            self.player.already_have_player_keys = True
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

        print(Colors.Yellow + "Ciphering each piece in deck" + Colors.Color_Off)

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
        padding = self.response.get("padding")
        self.player.npieces = self.response.get("pieces_per_player")

        print(Colors.Yellow + "Do you pick or pass?" + Colors.Color_Off)

        if random.random() < 0.05:
            print(Colors.Green + "Selecting a piece" + Colors.Color_Off)
            random.shuffle(pseudo_deck)
            padding.append(os.urandom(sys.getsizeof(pseudo_deck[-1])))
            self.player.encrypted_hand.append(pseudo_deck.pop())
        else:
            random.shuffle(pseudo_deck)

        players_nicks = list(self.player.aes_player_keys_dec.keys())
        player_to_send_deck = random.choice(players_nicks)

        encrypted_message = pickle.dumps({'action': "selection_stage", "deck": pseudo_deck,
                                          'pieces_per_player': self.response.get("pieces_per_player"),
                                          "stock_low": self.response.get("stock_low"), "padding": padding})

        encrypted_tuple = self.player.aes_player_keys_dec[player_to_send_deck].encrypt_aes_gcm(encrypted_message)

        msg = {'action': 'send_to_player', 'sender': self.player.name, 'rec': player_to_send_deck,
               'to_send': encrypted_tuple}

        return msg

    def _handle_selection_stage(self):
        # Picks a piece from the deck or passes, shuffles and sends to another player
        pseudo_deck = self.response.get("deck")
        padding = self.response.get("padding")
        self.player.npieces = self.response.get("pieces_per_player")
        print(Colors.Yellow + "Do you pick, substitute or pass?" + Colors.Color_Off)

        players_nicks = list(self.player.aes_player_keys_dec.keys())

        if len(self.player.encrypted_hand) < self.player.npieces:
            if random.random() < 0.60:
                print(Colors.Green + "Selecting a piece" + Colors.Color_Off)
                random.shuffle(pseudo_deck)
                padding.append(os.urandom(sys.getsizeof(pseudo_deck[-1])))
                self.player.encrypted_hand.append(pseudo_deck.pop())
            elif random.random() < 0.50 and len(self.player.encrypted_hand) > 0:
                # Substitute already selected pieces
                number_of_pieces_to_sub = random.randint(1, len(self.player.encrypted_hand))
                print(Colors.Green + "Substituting", number_of_pieces_to_sub, "pieces" + Colors.Color_Off)

                # For a certain number of pieces, take a new piece from deck and add one from hand.
                for piece in range(0, number_of_pieces_to_sub):
                    piece_to_put_in_deck = self.player.encrypted_hand.pop()
                    self.player.encrypted_hand.append(pseudo_deck.pop())
                    pseudo_deck.append(piece_to_put_in_deck)
                    random.shuffle(pseudo_deck)
            else:
                print(Colors.Green + "Passing" + Colors.Color_Off)
                random.shuffle(pseudo_deck)

        if len(pseudo_deck) > self.response.get("stock_low"):
            player_to_send_deck = random.choice(players_nicks)

            encrypted_message = pickle.dumps({'action': "selection_stage", "deck": pseudo_deck,
                                              'pieces_per_player': self.response.get("pieces_per_player"),
                                              'stock_low': self.response.get('stock_low'), "padding": padding})

            encrypted_tuple = self.player.aes_player_keys_dec[player_to_send_deck].encrypt_aes_gcm(encrypted_message)

            msg = {'action': 'send_to_player', 'sender': self.player.name, 'rec': player_to_send_deck,
                   'to_send': encrypted_tuple}
        else:
            print(Colors.Green + "Stock has reached low level. Stopping selection" + Colors.Color_Off)
            msg = {'action': 'selection_over', "deck": pseudo_deck}

        return msg

    def _handle_commit_hand(self):
        print(Colors.Yellow, "Generating hand commitment with starting encrypted deck", Colors.Color_Off)
        self.player.hand_commit = HandCommit(self.player.encrypted_hand.copy())

        signed_commit = self.keychain.sign(pickle.dumps(self.player.hand_commit.publishCommit()))

        print(Colors.Yellow, "Sending hand commitment", Colors.Color_Off)

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

    def _handle_reveal_keys(self):
        print(self.response.get("msg"))

        key_tuple_dict = {}

        keys_to_send = [keys for keys in self.player.randomized_tuple_mapping.keys() if
                        self.player.randomized_tuple_mapping[keys][0] not in self.player.pseudo_starting_stock]

        for key in keys_to_send:
            key_tuple_dict[self.player.randomized_tuple_mapping[key]] = key

        aux_encrypted_hand = []

        for piece in self.player.encrypted_hand:
            for tuple_piece in key_tuple_dict:
                if piece == tuple_piece[0]:
                    decipher = AESCipher(key_tuple_dict[tuple_piece])
                    deciphered_piece = pickle.loads(decipher.decrypt_aes_gcm(tuple_piece))
                    aux_encrypted_hand.append(deciphered_piece)

        self.player.encrypted_hand = aux_encrypted_hand

        print('size', sys.getsizeof(key_tuple_dict))
        print('dict', key_tuple_dict)

        return {'action': 'revealed_keys', 'keys_dict': key_tuple_dict}

    def _handle_keys_to_reveal(self):
        key_tuple_dict = self.response.get("keys_dict")
        aux_encrypted_hand = []

        print(Colors.BYellow + "Revealing Pieces" + Colors.Color_Off)

        for piece in self.player.encrypted_hand:
            for tuple_piece in key_tuple_dict:
                if piece == tuple_piece[0]:
                    decipher = AESCipher(key_tuple_dict[tuple_piece])
                    deciphered_piece = pickle.loads(decipher.decrypt_aes_gcm(tuple_piece))
                    aux_encrypted_hand.append(deciphered_piece)

        self.player.encrypted_hand = aux_encrypted_hand

        return {"action": "waiting_for_keys"}

    def _handle_piece_key_to_reveal(self):
        key_tuple_dict = self.response.get("key_dict")

        print(Colors.BYellow + "Revealing Piece" + Colors.Color_Off)

        for tuple_piece in key_tuple_dict:
            if tuple_piece[0] == self.player.new_piece:
                decipher = AESCipher(key_tuple_dict[tuple_piece])
                deciphered_piece = pickle.loads(decipher.decrypt_aes_gcm(tuple_piece))

        self.player.new_piece = deciphered_piece
        self.player.collected_keys[deciphered_piece] = key_tuple_dict

        if self.response.get("more"):
            msg = {"action": "request_piece_reveal", 'new_piece': self.player.new_piece,
                   'new_stock': self.player.pseudo_starting_stock}
        else:
            # Maybe needs to go ciphered for safety reasons?
            msg = {"action": "request_piece_deanon", "piece": deciphered_piece}

        return msg

    def _handle_keys_sent(self):
        return {'action': 'waiting_for_keys'}

    def _handle_start_deanon_stage(self):
        pub_key_list = self.response.get("pub_key_list")
        padding = self.response.get("padding")
        self.player.npieces = self.response.get("pieces_per_player")

        if random.random() < 0.05:
            print(Colors.BGreen + "Adding Public Key To Array" + Colors.Color_Off)
            padding.pop()
            padding.insert(0, None)
            tuple_to_add = self.player.encrypted_hand.pop()
            new_key = RSAKeychain(2048)
            self.player.tuple_keychains[tuple_to_add] = new_key
            pub_key_list[tuple_to_add[0]] = new_key.exportPubKey()
        else:
            print(Colors.BGreen + "Passing" + Colors.Color_Off)

        players_nicks = list(self.player.aes_player_keys_dec.keys())
        player_to_send_deck = random.choice(players_nicks)

        encrypted_message = pickle.dumps({'action': "deanon_stage", "pub_key_list": pub_key_list,
                                          'pieces_per_player': self.response.get("pieces_per_player"),
                                          "max_pieces": self.response.get("max_pieces"), "padding": padding})

        encrypted_tuple = self.player.aes_player_keys_dec[player_to_send_deck].encrypt_aes_gcm(encrypted_message)

        msg = {'action': 'send_to_player', 'sender': self.player.name, 'rec': player_to_send_deck,
               'to_send': encrypted_tuple}

        return msg

    def _handle_deanon_stage(self):
        pub_key_list = self.response.get("pub_key_list")
        padding = self.response.get("padding")
        self.player.npieces = self.response.get("pieces_per_player")

        players_nicks = list(self.player.aes_player_keys_dec.keys())

        if len(self.player.encrypted_hand) > 0:
            if random.random() < 0.60:
                print(Colors.BGreen + "Adding Public Key To Array" + Colors.Color_Off)
                padding.pop()
                padding.insert(0, None)
                new_key = RSAKeychain(2048)
                tuple_to_add = self.player.encrypted_hand.pop()
                self.player.tuple_keychains[tuple_to_add] = new_key
                pub_key_list[tuple_to_add[0]] = new_key.exportPubKey()
            else:
                print(Colors.BGreen + "Passing" + Colors.Color_Off)

        sum_check_done = sum(item is not None for item in pub_key_list)
        if sum_check_done < self.response.get('max_pieces'):
            player_to_send_deck = random.choice(players_nicks)

            encrypted_message = pickle.dumps({'action': "deanon_stage", "pub_key_list": pub_key_list,
                                              'pieces_per_player': self.response.get("pieces_per_player"),
                                              'max_pieces': self.response.get('max_pieces'), "padding": padding})

            encrypted_tuple = self.player.aes_player_keys_dec[player_to_send_deck].encrypt_aes_gcm(encrypted_message)

            msg = {'action': 'send_to_player', 'sender': self.player.name, 'rec': player_to_send_deck,
                   'to_send': encrypted_tuple}
        else:
            msg = {'action': 'deanon_prep_over', "pub_key_list": pub_key_list}

        return msg

    def _handle_decipher_tiles(self):
        tiles_to_decipher = self.response.get("ciphered_tiles")

        for tuple_piece in self.player.tuple_keychains:
            tile_to_decipher = tiles_to_decipher[tuple_piece[0]]
            tile_index = tuple_piece[0]
            cipher = self.player.tuple_keychains[tuple_piece]
            tile, tile_key = pickle.loads(cipher.decrypt(tile_to_decipher))
            if not hashFunctions.check_sha256_digest_from_list(tuple_piece[1], [str.encode(str(tile_index)), tile_key,
                                                                                str.encode(str(tile))]):
                print(Colors.Red + "SERVER IS CHEATING!" + Colors.Color_Off)
                exit(-1)
            self.player.insertInHand(tile)

        print(Colors.Green + "Hand has been de-anonymized!" + Colors.Color_Off)
        print("Hand -> " + ' '.join(map(str, self.player.hand)))
        return {"action": "ready_to_play"}

    def _handle_reveal_piece_key(self):
        key_tuple_dict = {}
        self.player.pseudo_starting_stock = self.response.get("new_stock")

        key_to_send = [keys for keys in self.player.randomized_tuple_mapping.keys() if
                       self.player.randomized_tuple_mapping[keys][0] in self.response.get("new_piece")]

        for key in key_to_send:
            key_tuple_dict[self.player.randomized_tuple_mapping[key]] = key

        print('size', sys.getsizeof(key_tuple_dict))
        print('dict', key_tuple_dict)

        return {'action': 'revealed_key_for_piece', 'key_dict': key_tuple_dict}

    def _handle_secret_message(self):
        if self.response.get('sender') == "server":
            cipher = self.player.server_aes_cipher
        else:
            cipher = self.player.aes_player_keys_dec[self.response.get('sender')]

        encrypted_tuple = self.response.get('msg')

        deciphered_msg = pickle.loads(cipher.decrypt_aes_gcm(encrypted_tuple))

        return deciphered_msg

    def _handle_insert_in_hand(self):
        tile, key = pickle.loads(self.response.get("new_tile"))
        print(Colors.Yellow + "Checking if server is not cheating" + Colors.Color_Off)
        if not hashFunctions.check_sha256_digest_from_list(self.player.new_piece[1],
                                                           [str.encode(str(self.player.new_piece[0])), key,
                                                            str.encode(str(tile))]):
            print(Colors.Red + "SERVER IS CHEATING!" + Colors.Color_Off)
            exit(-1)

        print(Colors.Green + "Tile is valid. Inserting in hand" + Colors.Color_Off, tile)
        self.player.insertInHand(tile)

        msg = self.player.play()
        if msg.get("action") == 'play_piece':
            piece_signature = self.keychain.sign(pickle.dumps(msg.get("piece")))
            msg.update({"signed_piece": piece_signature})
        return msg

    def _handle_validate_this_play(self):
        msg = {"action": "play_piece_ep"}
        self.player.nplayers = self.response.get("nplayers")
        self.player.npieces = self.response.get("npieces")
        self.player.pieces_per_player = self.response.get("pieces_per_player")
        self.player.in_table = self.response.get("in_table")
        last_table = self.request.get("last_table")

        if self.response.get("last_player") != self.player.name:
            print(Colors.Yellow + "Validating last played piece signature" + Colors.Color_Off)
            signed_piece = self.response.get("signed_piece")
            last_piece_played = self.response.get("last_piece")
            last_player = self.response.get("last_player")
            if not self.keychain.verify_sign(pickle.dumps(last_piece_played), signed_piece,
                                             readPublicKeyFromPEM(self.player.player_pub_keys[last_player])):
                print(Colors.Red + "This signature is not valid" + Colors.Color_Off)
                exit(-1)
            print(Colors.Green + "Last play signature is valid!" + Colors.Color_Off)

            if (self.player.validate(last_piece_played, last_table)):
                print("I don't know if the player cheated!")
                msg.update({"player_cheated": False})
            else:
                print("Cheated!")
                msg.update({"player_cheated": True})

        return msg

    def _handle_rcv_game_properties(self):
        self.player.nplayers = self.response.get("nplayers")
        self.player.npieces = self.response.get("npieces")
        self.player.pieces_per_player = self.response.get("pieces_per_player")
        self.player.in_table = self.response.get("in_table")
        player_name = self.response.get("next_player")

        if self.response.get("next_player") == self.player.name:
            player_name = Colors.BRed + "YOU" + Colors.Color_Off
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
                if self.player.isCheater:
                    msg = self.player.cheat_play()
                else:
                    msg = self.player.play()
                if msg.get("action") == 'play_piece':
                    piece_signature = self.keychain.sign(pickle.dumps(msg.get("piece")))
                    msg.update({"signed_piece": piece_signature})
                return msg

    def _handle_report_score(self):
        hand_commits_confirmations = self.response.get("hand_commits_confirmation")
        print(Colors.Yellow + "Validating all hand commits" + Colors.Color_Off)

        for player_name in self.player.players_commits:

            if not verifyHandCommit(self.player.players_commits[player_name][0],
                                    hand_commits_confirmations[player_name]):
                print(Colors.Red + player_name + " Sent an Invalid Hand Commit" + Colors.Color_Off)
            else:
                print(Colors.Green + player_name + " Sent a valid Hand Commit" + Colors.Color_Off)

        print(Colors.Yellow + "Calculating score for this game" + Colors.Color_Off)

        remaining_hands = self.response.get("remaining_hands")
        score_history = {}
        score = 0

        if self.response.get("winner") == "TIE":
            winner = None
            for player_name in remaining_hands:
                for piece in remaining_hands[player_name]:
                    score += piece.values[0].value + piece.values[1].value
                score_history[player_name] = score
            for player in score_history:
                if winner is None:
                    winner = player
                elif score_history[winner] > score_history[player]:
                    winner = player
            for player_name in score_history:
                if player_name != winner:
                    score += score_history[player_name]
        else:
            winner = self.response.get("winner")
            for player_name in remaining_hands:
                if player_name != winner:
                    for piece in remaining_hands[player_name]:
                        score += piece.values[0].value + piece.values[1].value

        print(Colors.Green, "I expect the winner to be ", winner, Colors.Color_Off)
        print(Colors.Green, "I expect the score to be ", score, Colors.Color_Off)
        self.player.calculated_score = score
        self.player.expected_winner = winner
        msg = {"action": "score_report", "score": score,
               "possible_winner": self.response.get("winner")}
        return msg

    def _handle_reveal_everything(self):
        next_action = self.response.get("next_act")
        if next_action == "validate_protest":
            print(Colors.Red + "There has been a protest!\n" + Colors.Color_Off)
        else:
            print(Colors.Yellow + "Game Ended!\n" + Colors.Color_Off)
            print("hand -> " + ' '.join(map(str, self.player.hand)))
            print("end table -> " + ' '.join(map(str, self.response.get("in_table"))) + "\n")
        print(Colors.Green + "Revealing everything to server!" + Colors.Color_Off)
        msg = {"action": next_action, "tile_keys": self.player.randomized_tuple_mapping,
               'hand_commit_confirmation': self.player.hand_commit.publishConfirmation(),
               "remaining_hand": self.player.hand, "collected_keys": self.player.collected_keys}
        return msg

    def _handle_end_game(self):
        winner = self.response.get("winner")
        score = self.response.get("score")
        print(Colors.Yellow, "Checking server score and winner", Colors.Color_Off)
        if winner != self.player.expected_winner:
            print(Colors.Red, "I don't agree with winner", Colors.Color_Off)
            exit(-1)
        if score != self.player.calculated_score:
            print(Colors.Red, "I don't agree with score", Colors.Color_Off)
            exit(-1)
        print(Colors.Green, "Agreeing with score and winner!", Colors.Color_Off)
        if self.response.get("winner") == self.player.name:
            winner = Colors.BRed + "YOU" + Colors.Color_Off
            print(Colors.BGreen + "End GAME, THE WINNER IS: " + winner)
            print(Colors.ICyan + "Your Score: " + str(score) + Colors.Color_Off)
            signature, data = self.cc.signData(str(score))
            msg = {"action": "assign_score", "signed_score": signature, "data": data, "player": self.player.name}
            return msg
        else:
            winner = Colors.BBlue + winner + Colors.Color_Off
            print(Colors.BGreen + "End GAME, THE WINNER IS: " + winner)
            print(("{} {} {} earned {} points {}".format(Colors.ICyan, winner, Colors.ICyan, str(score),
                                                         Colors.Color_Off)))

    def _handle_wait(self):
        print(self.response.get("msg"))

    def _handle_disconnect(self):
        self.close()
        input("PRESS ANY KEY TO EXIT ")
        print(self.response.get("msg"))
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
            if response is not None:
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
        elif action == "reveal_keys":
            response = self._handle_reveal_keys()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "keys_to_reveal":
            response = self._handle_keys_to_reveal()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "keys_sent":
            response = self._handle_keys_sent()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "start_deanon_stage":
            response = self._handle_start_deanon_stage()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "deanon_stage":
            response = self._handle_deanon_stage()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "decipher_tiles":
            response = self._handle_decipher_tiles()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "reveal_piece_key":
            response = self._handle_reveal_piece_key()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "piece_key_to_reveal":
            response = self._handle_piece_key_to_reveal()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "insert_in_hand":
            response = self._handle_insert_in_hand()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "validate_this_play":
            response = self._handle_validate_this_play()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "rcv_game_properties":
            response = self._handle_rcv_game_properties()
            if response is not None:
                message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                                  self.aes_cipher)
                self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "report_score":
            response = self._handle_report_score()
            if response is not None:
                message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                                  self.aes_cipher)
                self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "reveal_everything":
            response = self._handle_reveal_everything()
            message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                              self.aes_cipher)
            self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "end_game":
            response = self._handle_end_game()
            if response is not None:
                message = Message(self.selector, self.sock, self.addr, response, self.player, self.keychain, self.cc,
                                  self.aes_cipher)
                self.selector.modify(self.sock, selectors.EVENT_WRITE, data=message)
        elif action == "wait":
            self._handle_wait()
        elif action == "disconnect":
            self._handle_disconnect()
