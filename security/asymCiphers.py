from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256


class RSAKeychain:
    def __init__(self, key_size=2048):
        self.keyPair = RSA.generate(key_size)
        self.pubKey = self.keyPair.publickey()

    def encrypt(self, msg, pub_key=None):
        if pub_key is None:
            pub_key = self.pubKey

        encryptor = PKCS1_OAEP.new(pub_key)
        encrypted = encryptor.encrypt(msg)

        return encrypted

    def decrypt(self, msg):
        decryptor = PKCS1_OAEP.new(self.keyPair)
        decrypted = decryptor.decrypt(msg)
        return decrypted

    def sign(self, msg):
        hashed_msg = SHA256.new(msg)
        signer = PKCS115_SigScheme(self.keyPair)
        signature = signer.sign(hashed_msg)
        return signature

    def verify_sign(self, msg, signature, pub_key=None):
        if pub_key is None:
            pub_key = self.pubKey
        is_valid = True
        hashed_msg = SHA256.new(msg)
        verifier = PKCS115_SigScheme(pub_key)
        try:
            verifier.verify(hashed_msg, signature)
        except ValueError:
            is_valid = False

        return is_valid

    def getPubKey(self):
        return self.pubKey

    def exportPubKey(self):
        return self.pubKey.exportKey()
