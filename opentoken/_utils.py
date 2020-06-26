"""OpenToken utility functions
"""

import json
import re
from collections import OrderedDict


def validate_cipher_suite_id(cipher_suite_id):
    """Validates that a CipherSuite conforms to the proper format.

    Args:
        cipher_suite_id (int): CipherSuite id.

    Returns:
        (int): The original CipherSuite id.

    """
    if not isinstance(cipher_suite_id, int):
        raise TypeError("CipherSuite ID must be of type int.")
    if not 0 <= cipher_suite_id <= 3:
        raise ValueError("Invalid CipherSuite.")
    return cipher_suite_id


def validate_password(password):
    """Validate and reformat password argument.

    Args:
        password (str or bytes): Encryption password.

    Returns:
        str or bytes: The original password string.

    """
    if password is None:
        password = ""

    if not isinstance(password, str) and not isinstance(password, bytes):
        raise TypeError("Invalid password type")

    return password


def validate_payload(payload):
    """Validate that the payload is of type OrderedDict.
    If the payload is of type str, then it assumes that the string is
    able to be parsed via json.

    Args:
        payload (str or OrderedDict): Payload object

    Returns:
        OrderedDict: Original payload object as an OrderedDict.

    """
    if isinstance(payload, str):
        payload = json.JSONDecoder(
            object_pairs_hook=OrderedDict
        ).decode(payload)
    if not isinstance(payload, OrderedDict):
        raise TypeError("Payload must be of type OrderedDict.")
    return payload


def reformat_to_otk_b64(token):
    """Reformat a base64 encoded token to OpenToken standards,
    which replaces all base64 padding characters "=" with "*".

    Args:
        token (str): The base64 encoded token to reformat.

    Returns:
        (str): The reformatted base64 encoded string.

    """
    if re.match(r"^.*={2}$", token):
        token = token[:-2] + "**"
    elif re.match(r"^.*=$", token):
        token = token[:-1] + "*"
    return token


def reformat_from_otk_b64(token):
    """Reformat a base64 encoded token from OpenToken standards,
    which replaces all base64 padding characters "*" with "=".

    Args:
        token (str): The base64 encoded token to reformat.

    Returns:
        (str): The reformatted base64 encoded string.

    """
    if re.match(r"^.*\*{2}$", token):
        token = token[:-2] + "=="
    elif re.match(r"^.*\*$", token):
        token = token[:-1] + "="
    return token


def ordered_dict_to_otk_str(otk_dict):
    """Converts an OrderedDict to a OpenToken string.

    Args:
        otk_dict (OrderedDict): OrderedDict representation of the token.

    Returns:
        str: String representation of the token.

    """
    otk_list = []
    for k, v in otk_dict.items():
        otk_list.append("{0}={1}".format(k, v))
    return "\n".join(otk_list)


def otk_str_to_ordered_dict(otk_str):
    """Converts an OrderedDict to a OpenToken string.

    Args:
        otk_str (str): String representation of the token.

    Returns:
        OrderedDict: OrderedDict representation of the token.

    """
    items = otk_str.split("\n")
    pairs = [tuple(line.split("=")) for line in items if line != ""]
    return OrderedDict(pairs)
