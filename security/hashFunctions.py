#!/usr/bin/env python3
# Collection of hash functions utils

from hashlib import sha256


def get_sha256_digest_from_list(list_to_digest):
    h = sha256()

    for item in list_to_digest:
        h.update(item)

    return h.hexdigest()


def check_sha256_digest_from_list(digest_to_check, list_to_digest):
    digest_from_list = get_sha256_digest_from_list(list_to_digest)

    if digest_from_list == digest_to_check:
        return True
    else:
        return False
