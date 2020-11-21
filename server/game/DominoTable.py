#!/usr/bin/env python3
# DominoTable
# A class to simulate the board of a domino game
# Only adds pieces if they are legal
from server.game.DominoPiece import DominoPiece


class DominoTable:

    def __init__(self):
        self.table = []

    # domino - Domino Piece
    # side - 'l' or 'r'
    # returns True if piece was added, false if not
    def add_domino(self, domino, side):
        if side == 'l':
            return self.__add_domino_left(domino)
        elif side == 'r':
            return self.__add_domino_right(domino)
        else:
            return False

    def __add_domino_left(self, domino):

        if not self.table:
            self.table.append(domino)
            return True
        elif domino.piece[0] == self.table[0].piece[0]:
            self.table.insert(0, self.__invert_piece(domino))
            return True
        elif domino.piece[1] == self.table[0].piece[0]:
            self.table.insert(0, domino)
            return True
        else:
            return False

    def __add_domino_right(self, domino):

        if not self.table:
            self.table.append(domino)
            return True
        elif domino.piece[0] == self.table[-1].piece[1]:
            self.table.append(domino)
            return True
        elif domino.piece[1] == self.table[-1].piece[1]:
            self.table.append(self.__invert_piece(domino))
            return True
        else:
            return False

    @staticmethod
    def __invert_piece(domino):
        return DominoPiece(domino.piece[1], domino.piece[0])

    def __str__(self):
        return ''.join(str(domino) for domino in self.table)


#if __name__ == '__main__':
#    piece1 = DominoPiece(1, 2)
#    piece2 = DominoPiece(3, 2)
#    piece3 = DominoPiece(1, 6)
#    table = DominoTable()

#    table.add_domino(piece1, 'l')
#    table.add_domino(piece2, 'r')
#    table.add_domino(piece3, 'l')
#    print(table)
