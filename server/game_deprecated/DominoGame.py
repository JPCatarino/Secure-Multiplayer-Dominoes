#!/usr/bin/env python3
# DominoGame
# A class with the managing functions of a domino game
from random import shuffle
from server.game.DominoPiece import DominoPiece
from server.game.DominoTable import DominoTable


# Generate a classic double six domino set and shuffles it
def generateStock():
    stock = [DominoPiece(x, y) for x in range(7) for y in range(x, 7)]
    shuffle(stock)
    return stock


if __name__ == '__main__':
    d = generateStock()

