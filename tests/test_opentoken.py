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
        otk = "T1RLAQKlXlVqRz5Nkk1t5pO7mlphIkyyzBA6zX7LBM_pifrj7y8PsftHAAB" \
              "g4pyRMm9uxpjfupBqbOqedO5ixZ1oedBdlvYHOTmDnN0RSlAdLAbKHy2kQW" \
              "S-Hg0xUIqSRzuFbj8HWZWmsjB8Ioz6o8PNAF6uKlGJn3Y45TtSzwRmzLhHN" \
              "DMvTWKX2DdL"
        with pytest.raises(ValueError) as err:
            otkapi.parse_token(otk)
        assert str(err.value) == (
            "Must not use this token before 4019-01-02T03:04:05Z."
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
