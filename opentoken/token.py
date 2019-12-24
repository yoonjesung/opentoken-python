"""Token helper methods
"""

import base64
from collections import OrderedDict
from zlib import compress, decompress

from Crypto.Cipher import AES, DES3
from Crypto.Hash import SHA1, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from opentoken import ciphersuite, utils


def encode(payload, cipher_suite_id, password=None):
    """Generate an OpenToken from a given payload.

    OTK uses a simple, line-based format for encoding the key-value pairs
    in the payload. The format is encoded with UTF-8 and thus is
    guaranteed to support the transport of multi-byte characters.

    Args:
        payload (OrderedDict): Data to encrypt.
        cipher_suite_id (int): Cipher suite id.
        password (str): Password used for encryption/decryption.

    """
    payload = utils.validate_payload(payload)
    cipher_suite_id = utils.validate_cipher_suite_id(cipher_suite_id)
    password = utils.validate_password(password)

    cipher = ciphersuite.CIPHERS[cipher_suite_id]

    otk_version = 1
    encryption_key = ciphersuite.generate_key(password, cipher_suite_id)
    iv_length = cipher["iv_length"]
    payload = bytes(utils.ordered_dict_to_otk_str(payload), "utf-8")
    iv = get_random_bytes(iv_length)

    if cipher_suite_id == 0:
        hmac = SHA1.new()
    else:
        hmac = HMAC.new(encryption_key, digestmod=SHA1)
    hmac.update(bytearray([otk_version]))
    hmac.update(bytearray([cipher_suite_id]))
    if iv_length > 0:
        hmac.update(iv)
    hmac.update(payload)
    hmac_digest = hmac.digest()

    zipped_data = compress(payload)

    if cipher_suite_id == 3:
        cipher_type = DES3
    else:
        cipher_type = AES
    cipher = cipher_type.new(encryption_key, cipher_type.MODE_CBC, iv=iv)
    payload_cipher_text = cipher.encrypt(
        pad(zipped_data, cipher_type.block_size)
    )

    otk_buffer = bytearray("OTK", "utf-8")  #: OTK literal
    otk_buffer.append(1)  #: Version identifier
    otk_buffer.append(cipher_suite_id)  #: Cipher suite identifier
    otk_buffer.extend(hmac_digest)  #: SHA-1 HMAC
    otk_buffer.append(iv_length)  #: IV Length
    if iv_length > 0:
        otk_buffer.extend(iv)  #: IV
    otk_buffer.append(0)  #: Key info length
    otk_buffer.extend(
        int(len(payload_cipher_text)).to_bytes(
            2, byteorder="big", signed=False
        )
    )  #: Payload length
    otk_buffer.extend(payload_cipher_text)  #: Payload

    otk = base64.urlsafe_b64encode(otk_buffer).decode("utf-8")
    return utils.reformat_to_otk_b64(otk)


def decode(otk, cipher_suite_id, password=None):
    """Decode an OpenToken.

    Args:
        otk (str): Base64 encoded OpenToken with "*" padding chars.
        cipher_suite_id (int): Cipher suite id.
        password (str): Password used for encryption/decryption.

    """
    cipher_suite_id = utils.validate_cipher_suite_id(cipher_suite_id)
    password = utils.validate_password(password)

    decryption_key = ciphersuite.generate_key(password, cipher_suite_id)
    otk = utils.reformat_from_otk_b64(otk)
    read_index = 0
    otk = bytearray(base64.urlsafe_b64decode(otk))

    #: Validate the OTK header literal
    otk_header = otk[read_index:read_index + 3].decode()
    read_index += 3
    if otk_header != "OTK":
        raise ValueError(
            "Invalid token header literal: {0}".format(otk_header)
        )

    #: Validate version
    otk_version = int.from_bytes(otk[read_index:read_index + 1], "big")
    read_index += 1
    if otk_version != 1:
        raise ValueError("Invalid OTK version.")

    #: Validate CipherSuite id
    otk_cipher_suite_id = int.from_bytes(otk[read_index:read_index + 1], "big")
    read_index += 1
    if otk_cipher_suite_id != cipher_suite_id:
        raise ValueError(
            "CipherID, {0}, doesn't match the encoding cipher, {1}.".format(
                otk_cipher_suite_id, cipher_suite_id
            )
        )

    #: Extract cipher, mac and iv information
    hmac = otk[read_index:read_index + 20]
    read_index += 20
    iv_length = int.from_bytes(otk[read_index:read_index + 1], "big")
    read_index += 1
    iv = None
    if iv_length > 0:
        iv = otk[read_index:read_index + iv_length]
        read_index += iv_length

    #: Extract the Key Info (if present) and select a key for decryption
    key_info_length = int.from_bytes(otk[read_index:read_index + 1], "big")
    read_index += 1
    key_info = None
    if key_info_length > 0:
        key_info = otk[read_index:read_index + key_info_length]
        read_index += key_info_length

    #: Decrypt the payload cipher-text using the selected cipher suite
    payload_cipher_text = None
    payload_length = int.from_bytes(
        otk[read_index:read_index + 2], "big", signed=False
    )
    read_index += 2
    payload_cipher_text = otk[read_index:read_index + payload_length]

    if cipher_suite_id == 3:
        cipher_type = DES3
    else:
        cipher_type = AES
    cipher = cipher_type.new(decryption_key, cipher_type.MODE_CBC, iv=iv)
    try:
        zipped_data = unpad(
            cipher.decrypt(payload_cipher_text), cipher_type.block_size
        )
    except ValueError:
        raise ValueError("Error decrypting token.")

    #: Decompress the decrypted payload in accordance with RFC1950 and RFC1951
    payload = decompress(zipped_data)

    #: Initialize an HMAC using the SHA-1 algorithm and the following data -
    #: OTK Version, Cipher Suite Value, IV value, Key info value (if present)
    if cipher_suite_id == 0:
        hmac_test = SHA1.new()
    else:
        hmac_test = HMAC.new(decryption_key, digestmod=SHA1)
    hmac_test.update(bytearray([otk_version]))
    hmac_test.update(bytearray([cipher_suite_id]))
    if iv_length > 0:
        hmac_test.update(iv)
    if key_info:
        hmac_test.update(key_info)
    hmac_test.update(payload)

    #: Compare reconstructed HMAC with original HMAC
    if hmac_test.hexdigest() != hmac.hex():
        raise ValueError("HMAC does not match.")

    return utils.otk_str_to_ordered_dict(payload.decode())
