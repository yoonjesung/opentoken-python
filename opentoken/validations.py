from typing import Union


def validate_cipher_suite_id(cipher_suite_id: int) -> int:
    """Validates that a CipherSuite conforms to the proper format.

    Args:
        cipher_suite_id: CipherSuite id.

    Returns:
        The original CipherSuite id.

    """
    if not isinstance(cipher_suite_id, int):
        raise TypeError("CipherSuite ID must be of type int.")
    if not 0 <= cipher_suite_id <= 3:
        raise ValueError("Invalid CipherSuite.")
    return cipher_suite_id


def validate_password(password: Union[str, bytes]) -> bytes:
    """Validate and reformat password argument.

    Args:
        password: Byte or string encryption password.

    Returns:
        The byte representation of the password.

    """
    if password is None:
        password = b""

    if isinstance(password, str):
        password = bytes(password, "utf-8")

    if not isinstance(password, bytes):
        raise TypeError("Invalid password type")

    return password
