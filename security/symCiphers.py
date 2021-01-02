# Simple authenticated AES implementation
# Based on the examples of the book Practical Cryptography for Developers by Svetlin Nakov
from Crypto.Cipher import AES
import os


class AESCipher:
    def __init__(self, secret=None):
        if secret is None:
            self.secret = os.urandom(32)
        else:
            self.secret = secret

    def encrypt_aes_gcm(self, msg):
        cipher = AES.new(self.secret, AES.MODE_GCM)
        ciphertext, auth_tag = cipher.encrypt_and_digest(msg)
        return ciphertext, cipher.nonce, auth_tag

    def decrypt_aes_gcm(self, ciphered_msg, secret=None):
        if secret is None:
            secret = self.secret
        (ciphertext, nonce, auth_tag) = ciphered_msg
        cipher = AES.new(secret, AES.MODE_GCM, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
        return plaintext

