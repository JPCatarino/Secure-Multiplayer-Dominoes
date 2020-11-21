#!/usr/bin/env python3
# DominoTable
# A class to simulate a piece of Domino

class DominoPiece:

    # Creates a domino piece with 2 integers
    def __init__(self, int1, int2):
        self.piece = (int1, int2)

    def __str__(self):
        return '[{}|{}]'.format(self.piece[0], self.piece[1])
