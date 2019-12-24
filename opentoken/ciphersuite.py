"""CipherSuite helper module
"""

from Crypto.Protocol.KDF import PBKDF2

from opentoken import utils

CIPHERS = [
    {
        "id": 0,
        "name": None,
        "cipher": None,
        "key_size": 0,
        "mode": None,
        "padding": None,
        "iv_length": 0
    },
    {
        "id": 1,
        "name": "aes-256-cbc",
        "cipher": "AES",
        "key_size": 256,
        "mode": "CBC",
        "padding": "PKCS 5",
        "iv_length": 16
    },
    {
        "id": 2,
        "name": "aes-128-cbc",
        "cipher": "AES",
        "key_size": 128,
        "mode": "CBC",
        "padding": "PKCS 5",
        "iv_length": 16
    },
    {
        "id": 3,
        "name": "3des",
        "cipher": "3DES",
        "key_size": 168,
        "mode": "CBC",
        "padding": "PKCS 5",
        "iv_length": 8
    }
]


def generate_key(password, cipher_suite_id, salt=None):
    password = utils.validate_password(password)
    cipher_suite_id = utils.validate_cipher_suite_id(cipher_suite_id)

    if cipher_suite_id == 0:
        return None

    salt = salt or bytearray([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    cipher_suite = CIPHERS[cipher_suite_id]

    return PBKDF2(
        password,
        salt,
        dkLen=cipher_suite["key_size"] // 8,
    )
