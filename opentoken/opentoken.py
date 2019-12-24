"""OpenToken module for Python
"""


class OpenToken:
    """API class for generating and reading OpenTokens.

    Args:
        password (str): Password used for encryption/decryption.
        cipher_suite_id (int): Cipher suite id.
        token_tolerance (int): Token tolerance.
        token_lifetime (int): Token lifetime.
        token_renewal (int): Token renewal.

    """

    def __init__(self, password, cipher_suite_id=2, token_tolerance=120,
                 token_lifetime=300, token_renewal=43200):
        self.cipher_suite_id = cipher_suite_id
        self.password = password
        self.token_tolerance = token_tolerance
        self.token_lifetime = token_lifetime
        self.token_renewal = token_renewal

    def parse_token(self):
        """Parse an OpenToken and apply basic validation checks.

        """
        raise NotImplementedError

    def create_token(self):
        """Create an OpenToken from an object of key-value pairs to encode.

        """
        raise NotImplementedError
