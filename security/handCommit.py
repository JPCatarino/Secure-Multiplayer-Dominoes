import hashFunctions
import os
import pickle


def verifyHandCommit(commit, confirmation):
    b = hashFunctions.get_sha256_digest_from_list([commit[0], confirmation[0], pickle.dumps(confirmation[1])])
    return b == commit[1]


class HandCommit:

    def __init__(self, t):
        self.t = t
        self.r1 = os.urandom(32)
        self.r2 = os.urandom(32)
        self.b = hashFunctions.get_sha256_digest_from_list([self.r1, self.r2, pickle.dumps(self.t)])

    def publishCommit(self):
        return self.r1, self.b

    def publishConfirmation(self):
        return self.r2, self.t

