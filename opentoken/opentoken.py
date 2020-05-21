"""OpenToken module for Python
"""

import datetime
from collections import OrderedDict

import dateutil.parser

from . import _token


class OpenToken:
    """API class for generating and reading OpenTokens.

    Args:
        password (str): Password used for encryption/decryption.
        cipher_suite_id (int): Cipher suite id.
        token_tolerance (int): Token tolerance.
        token_lifetime (int): Token lifetime.
        token_renewal (int): Token renewal.

    """

    def __init__(self, password=None, cipher_suite_id=2, token_tolerance=120,
                 token_lifetime=300, token_renewal=43200):
        self.cipher_suite_id = cipher_suite_id
        self.password = password
        self.token_tolerance = token_tolerance
        self.token_lifetime = token_lifetime
        self.token_renewal = token_renewal

    def parse_token(self, otk_str):
        """Parse an OpenToken and apply basic validation checks.

        Args:
            otk_str (str): The raw base64 encoded token string.

        Returns:
            OrderedDict: The key-value token pairs.

        """
        parsed_token = _token.decode(
            otk_str, self.cipher_suite_id, self.password
        )

        if "subject" not in parsed_token.keys():
            raise ValueError("OpenToken missing 'subject'.")

        not_before = dateutil.parser.isoparse(parsed_token['not-before'])
        not_on_or_after = dateutil.parser.isoparse(
            parsed_token['not-on-or-after']
        )
        renew_until = dateutil.parser.isoparse(parsed_token['renew-until'])
        now = datetime.datetime.now(datetime.timezone.utc)
        tolerance = now + datetime.timedelta(seconds=self.token_tolerance)

        if not_before > not_on_or_after:
            raise ValueError(
                "Logical error in 'not-before' and 'not-on-or-after'."
            )

        if not_before > now and not_before > tolerance:
            raise ValueError("Must not use this token before {0}.".format(
                parsed_token['not-before']
            ))

        if now > not_on_or_after:
            raise ValueError("This token has expired as of {0}.".format(
                parsed_token['not-on-or-after']
            ))

        if now > renew_until:
            raise ValueError(
                "This token is past its renewal limit, {0}.".format(
                    parsed_token['renew-until']
                )
            )

        return parsed_token

    def create_token(self, otk_pairs):
        """Create an OpenToken from an object of key-value pairs to encode.

        Args:
            otk_pairs (list): The key-value token pairs as a list of tuples.

        Returns:
            str: The raw base64 encoded token string.

        """
        otk_dict = OrderedDict(otk_pairs)

        if "subject" not in otk_dict.keys():
            raise ValueError("OpenToken missing 'subject'.")

        now = datetime.datetime.now(datetime.timezone.utc)
        expiry = now + datetime.timedelta(seconds=self.token_lifetime)
        renew_until = now + datetime.timedelta(seconds=self.token_renewal)

        otk_dict['not-before'] = now.isoformat()
        otk_dict['not-on-or-after'] = expiry.isoformat()
        otk_dict['renew-until'] = renew_until.isoformat()

        return _token.encode(otk_dict, self.cipher_suite_id, self.password)
