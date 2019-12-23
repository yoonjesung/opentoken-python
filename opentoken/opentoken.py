"""OpenToken module for Python
"""


class OpenToken:
    """API class for generating and reading OpenTokens.

    Args:
        cipher_suite (int): Cipher suite id.
        password (str): Password used for encryption/decryption.
        kwargs (dict): Additional configuration keyword-arguments.

    """

    def __init__(self, cipher_suite, password, **kwargs):
        self.cipher_suite = cipher_suite
        self.password = password

        self.time_tolerance = kwargs.get(
            "tokenTolerance", 120
        ) * 1000  #: 2 minutes
        self.token_lifetime = kwargs.get(
            "tokenLifetime", 300
        ) * 1000  #: 5 minutes
        self.time_renewal = kwargs.get(
            "tokenRenewal", 43200
        ) * 1000  #: 12 hours

    def parse_token(self):
        """Parse an OpenToken and apply basic validation checks.

        """
        raise NotImplementedError

    def create_token(self):
        """Create an OpenToken from an object of key-value pairs to encode.

        """
        raise NotImplementedError
