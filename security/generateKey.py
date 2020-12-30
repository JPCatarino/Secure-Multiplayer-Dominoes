# Generates a key
# Created by JPCatarino - 28/10/2020
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import random
import string


# Generates a random string with letters and numbers
# Taken from pynative.com/python-generate-random-string/
def get_random_alphanumeric_string(length):
    letters_and_digits = string.ascii_letters + string.digits

    result_str = ''.join((random.choice(letters_and_digits) for i in range(length)))

    return result_str


# The PBKDF2 generator receives as input the number of bytes to generate instead of bits
def generate_key(pwd):
    salt = b'\x00'
    kdf = PBKDF2HMAC(hashes.SHA1(), 16, salt, 1000, default_backend())
    key = kdf.derive(bytes(pwd, 'UTF-8'))
    return key
