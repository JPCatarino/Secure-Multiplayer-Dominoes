from dominoes.deck_utils import Deck, Player


class Game:
    def __init__(self, max_players):
        if max_players > 2:
            self.deck = Deck(5)
        else:
            self.deck = Deck(7)
        print("Deck created \n", self.deck)
        self.max_players = max_players
        self.nplayers = 0
        self.players = []
        self.player_index = 0
        self.init_validation_count = 0
        self.players_commits = {}
        self.players_commits_confirmations = {}
        self.players_played_pieces = {}
        self.player_initial_hands = {}
        self.players_remaining_hands = {}
        self.players_collected_key = {}
        self.players_calculated_scores = {}
        self.players_possible_winner = {}
        self.game_winner = None
        self.init_distribution = True
        self.next_action = "play"
        self.started = False
        self.players_ready = False
        self.all_ready_to_play = False
        self.players_waiting = 0
        self.first_in_randomization = None
        self.score_history = {}
        self.score = 0
        self.cc_pub_keys = {}

    def checkDeadLock(self):
        return all([player.nopiece for player in self.players])

    def allPlayersWithPieces(self):
        return all([p.num_pieces == p.pieces_per_player for p in self.players])

    def currentPlayer(self):
        return self.players[self.player_index]

    def nextPlayer(self):
        self.player_index += 1
        if self.player_index == self.max_players:
            self.player_index = 0
        return self.players[self.player_index]

    def addPlayer(self, name, socket, pieces):
        self.nplayers += 1
        assert self.max_players >= self.nplayers
        player = Player(name, socket, pieces)
        print(player)
        self.players.append(player)

    def hasHost(self):
        return len(self.players) > 0

    def hasPlayer(self, name):
        for player in self.players:
            if name == player.name:
                return True
        return False

    def isFull(self):
        return self.nplayers == self.max_players

    def toJson(self):
        msg = {"next_player": self.players[self.player_index].name, "nplayers": self.nplayers
            , "next_action": self.next_action}
        msg.update(self.deck.toJson())
        return msg
