"""Unit tests for opentoken.py
"""

import pytest

from opentoken import opentoken


class TestOpenToken:
    def test_create_no_subject(self):
        with pytest.raises(ValueError) as err:
            otkapi = opentoken.OpenToken(password="testPassword")
            otkapi.create_token([
                ("no-subject", "foo")
            ])
        assert str(err.value) == "OpenToken missing 'subject'."

    def test_create_and_parse(self):
        otkapi = opentoken.OpenToken(password="testPassword")
        token = otkapi.create_token([
            ("subject", "foobar")
        ])
        parsed_token = otkapi.parse_token(token)
        assert parsed_token["subject"] == "foobar"

    def test_logic_error(self):
        otkapi = opentoken.OpenToken(
            password="testPassword", token_lifetime=-100
        )
        token = otkapi.create_token([
            ("subject", "foobar")
        ])
        with pytest.raises(ValueError) as err:
            otkapi.parse_token(token)
        assert str(err.value) == (
            "Logical error in 'not-before' and 'not-on-or-after'."
        )

    def test_not_before(self):
        otkapi = opentoken.OpenToken(password="testPassword")
        otk = "T1RLAQLkWqFnzhcAeHmemSskPxNJ2T3q_BAQFNJH_W9yOmOD5O16Jys" \
              "vAABwjtZzeZGKKoYAkWyhfwS1nPM-XYMUnj0GW8PvOlrNRRT54b7jOa" \
              "8acwP5Ax0vGmPThNGA8Unr4Wrt9vOEZ4-DeGxCk70XDLorFJP69uJsF" \
              "swjqlRQ2vJLOLuMl1goKuOLjWni8yMuctyLPwc4TEh5kA**"
        with pytest.raises(ValueError) as err:
            otkapi.parse_token(otk)
        assert str(err.value) == (
            "Must not use this token before 4019-01-22T15:55:30.973481+00:00."
        )

    def test_expired(self):
        otkapi = opentoken.OpenToken(
            password="testPassword", token_lifetime=0
        )
        token = otkapi.create_token([
            ("subject", "foobar")
        ])
        with pytest.raises(ValueError) as err:
            otkapi.parse_token(token)
        assert str(err.value).startswith(
            "This token has expired as of"
        ) is True

    def test_renewal_past(self):
        otkapi = opentoken.OpenToken(
            password="testPassword", token_renewal=0
        )
        token = otkapi.create_token([
            ("subject", "foobar")
        ])
        with pytest.raises(ValueError) as err:
            otkapi.parse_token(token)
        assert str(err.value).startswith(
            "This token is past its renewal limit,"
        ) is True
