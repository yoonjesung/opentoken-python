"""CipherSuite helper module
"""

from __future__ import absolute_import

import hashlib

from opentoken import validations

CIPHERS = [
    {
        "id": 0,
        "name": None,
        "cipher": None,
        "key_size": 0,
        "mode": None,
        "padding": None,
        "ivlength": 0
    },
    {
        "id": 1,
        "name": "aes-256-cbc",
        "cipher": "AES",
        "key_size": 256,
        "mode": "CBC",
        "padding": "PKCS 5",
        "ivlength": 16
    },
    {
        "id": 2,
        "name": "aes-128-cbc",
        "cipher": "AES",
        "key_size": 128,
        "mode": "CBC",
        "padding": "PKCS 5",
        "ivlength": 16
    },
    {
        "id": 3,
        "name": "3des",
        "cipher": "3DES",
        "key_size": 168,
        "mode": "CBC",
        "padding": "PKCS 5",
        "ivlength": 8
    }
]


def generate_key(password, cipher_suite_id, salt=None):
    password = validations.validate_password(password)
    cipher_suite_id = validations.validate_cipher_suite_id(cipher_suite_id)

    salt = salt or bytearray([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    cipher_suite = CIPHERS[cipher_suite_id]

    return hashlib.pbkdf2_hmac(
        "sha1",
        password,
        salt,
        1000,
        cipher_suite["key_size"] // 8
    )
