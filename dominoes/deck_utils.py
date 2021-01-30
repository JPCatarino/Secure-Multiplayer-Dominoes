import random

from security import generateKey as keygen
from security import hashFunctions
from utils import Colors


class Player:
    def __init__(self, name, socket, cheater, pieces_per_player=None):
        self.name = name
        self.socket = socket
        self.hand = []
        self.hand_commit = []
        self.encrypted_hand = []
        self.server_aes_cipher = None
        self.already_have_player_keys = False
        self.aes_player_keys = {}
        self.aes_player_keys_dec = {}
        self.player_pub_keys = {}
        self.players_commits = {}
        self.players_commits_confirmations = {}
        self.calculated_score = 0
        self.expected_winner = ""
        self.collected_keys = {}
        self.num_pieces = 0
        self.score = 0
        self.host = False
        self.pieces_per_player = pieces_per_player
        self.ready_to_play = False
        self.in_table = []
        self.deck = []
        self.pseudo_starting_stock = []
        self.nopiece = False

        self.player_registered = False
        self.tuple_keychains = {}
        self.new_piece = None

        self.isCheater = cheater


    def __str__(self):
        return str(self.toJson())

    def toJson(self):
        return {"name": self.name, "hand": self.hand, "score": self.score}

    def isHost(self):
        return self.host

    def pickPiece(self):
        if not self.ready_to_play and self.num_pieces == self.pieces_per_player:
            self.ready_to_play = True
        random.shuffle(self.deck)
        piece = self.deck.pop()
        self.insertInHand(piece)
        return {"action": "get_piece", "deck": self.deck}

    def pickAnonPiece(self):
        random.shuffle(self.pseudo_starting_stock)
        self.new_piece = self.pseudo_starting_stock.pop()

        return {"action": "request_piece_reveal", 'new_piece': self.new_piece, 'new_stock': self.pseudo_starting_stock}

    def updatePieces(self, i):
        self.num_pieces += i

    def canPick(self):
        return self.num_pieces < self.pieces_per_player

    def insertInHand(self, piece):
        self.num_pieces += 1
        self.hand.append(piece)
        self.hand.sort(key=lambda p: int(p.values[0].value) + int(p.values[1].value))

    def checkifWin(self):
        print("Winner ", self.num_pieces == 0)
        return self.num_pieces == 0

    def play(self):
        res = {}
        print("Player Pieces", self.num_pieces)
        if self.in_table == []:
            print("Empty table")
            piece = self.hand.pop()
            self.updatePieces(-1)
            res = {"action": "play_piece", "piece": piece, "edge": 0, "win": False}
        else:
            edges = self.in_table[0].values[0].value, self.in_table[len(self.in_table) - 1].values[1].value
            print(str(edges[0]) + " " + str(edges[1]))
            max = 0
            index = 0
            edge = None
            flip = False
            # get if possible the best piece to play and the correspondent assigned edge
            for i, piece in enumerate(self.hand):
                aux = int(piece.values[0].value) + int(piece.values[1].value)
                if aux > max:
                    if int(piece.values[0].value) == int(edges[0]):
                        max = aux
                        index = i
                        flip = True
                        edge = 0
                    elif int(piece.values[1].value) == int(edges[0]):
                        max = aux
                        index = i
                        flip = False
                        edge = 0
                    elif int(piece.values[0].value) == int(edges[1]):
                        max = aux
                        index = i
                        flip = False
                        edge = 1
                    elif int(piece.values[1].value) == int(edges[1]):
                        max = aux
                        index = i
                        flip = True
                        edge = 1
            # if there is a piece to play, remove the piece from the hand and check if the orientation is the correct
            if edge is not None:
                piece = self.hand.pop(index)
                if flip:
                    piece.flip()
                self.updatePieces(-1)
                res = {"action": "play_piece", "piece": piece, "edge": edge, "win": self.checkifWin()}
            # if there is no piece to play try to pick a piece, if there is no piece to pick pass
            else:
                if len(self.pseudo_starting_stock) > 0:
                    res = self.pickAnonPiece()
                else:
                    res = {"action": "pass_play", "piece": None, "edge": edge, "win": self.checkifWin()}
            print("To play -> " + str(piece))
        return res

    def cheat_play(self):
        res = {}
        if self.in_table == []:
            print("Empty table")
            piece = self.hand.pop()
            self.updatePieces(-1)
            res = {"action": "play_piece", "piece": piece, "edge": 0, "win": False}
        else:
            edges = self.in_table[0].values[0].value, self.in_table[len(self.in_table) - 1].values[1].value
            print(str(edges[0]) + " " + str(edges[1]))
            max = 0
            index = 0
            edge = None
            flip = False
            # get if possible the best piece to play and the correspondent assigned edge
            for i, piece in enumerate(self.hand):
                aux = int(piece.values[0].value) + int(piece.values[1].value)
                if aux > max:
                    if int(piece.values[0].value) == int(edges[0]):
                        max = aux
                        index = i
                        flip = True
                        edge = 0
                    elif int(piece.values[1].value) == int(edges[0]):
                        max = aux
                        index = i
                        flip = False
                        edge = 0
                    elif int(piece.values[0].value) == int(edges[1]):
                        max = aux
                        index = i
                        flip = False
                        edge = 1
                    elif int(piece.values[1].value) == int(edges[1]):
                        max = aux
                        index = i
                        flip = True
                        edge = 1
            # if there is a piece to play, remove the piece from the hand and check if the orientation is the correct
            if edge is not None:
                piece = self.hand.pop(index)
                if flip:
                    piece.flip()
                self.updatePieces(-1)
                res = {"action": "play_piece", "piece": piece, "edge": edge, "win": self.checkifWin()}

            # if there is no piece to play try to cheat. No need to pick/pass, because...who needs that?
            else:
                #verificar as peças da mesa e ver que números edge que estão na jogada
                #trocar uma da mão para a tornar jogável
                #jogar essa peça
                edges = self.in_table[0].values[0].value, self.in_table[len(self.in_table) - 1].values[1].value
                pieceToSwitch = self.hand.pop()
                self.updatePieces(-1)
                cheatedPiece = Piece(edges[0], edges[1])
                self.insertInHand(cheatedPiece)
                print(Colors.Red + "Forging a Piece, MUAHAHAHA" + Colors.Color_Off)

                piece = self.hand.pop(self.hand.index(cheatedPiece))
                if flip:
                    piece.flip()
                self.updatePieces(-1)
                res = {"action": "play_piece", "piece": cheatedPiece, "edge": edge, "win": self.checkifWin()}
            print("To play -> " + str(piece))
        return res

    def validate(self, piece, last_table):
        valid_play = [None]*2
        if last_table:
            for piece_in_table in last_table:
                if piece == piece_in_table:
                    valid_play[0] = False   #illegal move, piece already played in table
                    break
                else:
                    valid_play[0] = True
        else: 
            valid_play[0] = True
        for piece_in_hand in self.hand:
            if piece == piece_in_hand:
                valid_play[1] = False  # illegal move, piece in someone's hands
                break
            else:
                valid_play[1] = True

        if valid_play[0] == valid_play[1] == True:
            return True   #legal play
        else:
            return False  #ilegal play

class Piece:
    values = []

    def __init__(self, first, second):
        self.values = [SubPiece(first), SubPiece(second)]

    def __str__(self):
        return " {}:{}".format(str(self.values[0]), str(self.values[1]))

    def __eq__(self, other):
        if not isinstance(other, Piece):
            # don't attempt to compare against unrelated types
            return NotImplemented

        return (self.values[0].value == other.values[0].value and self.values[1].value == other.values[1].value) or \
               (self.values[0].value == other.values[1].value and self.values[1].value == other.values[0].value) or \
               (self.values[1].value == other.values[0].value and self.values[0].value == other.values[1].value)

    def flip(self):
        self.values = [self.values[1], self.values[0]]


class SubPiece:
    value = None

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "\033[1;9{}m{}\033[0m".format(int(self.value) + 1, self.value)


class Deck:
    deck = []
    pseudo_deck = []
    pseudo_table = []
    tile_keys_per_player = {}

    def __init__(self, pieces_per_player=5):
        self.deck = [Piece(x, y) for x in range(7) for y in range(x, 7)]
        random.shuffle(self.deck)
        self.npieces = len(self.deck)
        self.pieces_per_player = pieces_per_player
        self.in_table = []

    def __str__(self):
        a = ""
        for piece in self.deck:
            a += str(piece)
        return a

    def generate_pseudonymized_deck(self):
        for tile in self.deck:
            tile_index = self.deck.index(tile)
            tile_key = keygen.generate_key(keygen.get_random_alphanumeric_string(8))
            self.pseudo_table.append(tile_key)
            tile_hash = hashFunctions.get_sha256_digest_from_list(
                [str.encode(str(tile_index)), tile_key, str.encode(str(tile))])
            pseudo_tuple = (tile_index, tile_hash)
            self.pseudo_deck.append(pseudo_tuple)

    def toJson(self):
        return {"npieces": self.npieces, "pieces_per_player": self.pieces_per_player, "in_table": self.in_table}
