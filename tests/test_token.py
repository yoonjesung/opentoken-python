"""Unit tests for _token.py
"""

import base64
from collections import OrderedDict
from unittest.mock import patch

import pytest

from opentoken import _token, _utils


class TestToken:
    canonical_payload = OrderedDict([
        ("foo", "bar"),
        ("bar", "baz"),
    ])

    def test_decode_invalid_header(self):
        encoded = base64.urlsafe_b64encode(bytearray(b'CTK'))
        otk = _utils.reformat_to_otk_b64(encoded.decode())
        with pytest.raises(ValueError) as err:
            _token.decode(otk, 2)
        assert str(err.value) == "Invalid token header literal: CTK"

    def test_decode_invalid_version(self):
        encoded = base64.urlsafe_b64encode(bytearray(b'OTK\x02'))
        otk = _utils.reformat_to_otk_b64(encoded.decode())
        with pytest.raises(ValueError) as err:
            _token.decode(otk, 2)
        assert str(err.value) == "Invalid OTK version."

    def test_decode_invalid_cipher_suite_id(self):
        encoded = base64.urlsafe_b64encode(bytearray(b'OTK\x01\x03'))
        otk = _utils.reformat_to_otk_b64(encoded.decode())
        with pytest.raises(ValueError) as err:
            _token.decode(otk, 2)
        assert str(err.value) == (
            "CipherID, 3, doesn't match the encoding cipher, 2."
        )

    def test_decode_invalid_password(self):
        otk = "T1RLAQLVVgI6nfAXif1wYQz-4Hoqqjpk-RCRhrYo_A3vfozy8DwQgX_" \
              "iAAAgXtSyTiGFVbQGmJ7-USFFjaZYuPueXSr8Gl2W5APuFWw*"
        with pytest.raises(ValueError) as err:
            _token.decode(otk, 2, "badPassword")
        assert str(err.value) == "Error decrypting token."

    def test_decode_aes_128_self_assigned_password(self):
        otk = "T1RLAQLVVgI6nfAXif1wYQz-4Hoqqjpk-RCRhrYo_A3vfozy8DwQgX_" \
              "iAAAgXtSyTiGFVbQGmJ7-USFFjaZYuPueXSr8Gl2W5APuFWw*"
        payload = _token.decode(otk, 2, "testPassword")
        expected_payload = OrderedDict([
            ("subject", "foobar"),
            ("foo", "bar"),
            ("bar", "baz"),
        ])
        assert payload == expected_payload

    @patch("opentoken._ciphersuite.generate_key")
    def test_decode_aes_128_canonical(self, decryption_key_mock):
        decryption_key_mock.return_value = base64.standard_b64decode(
            "a66C9MvM8eY4qJKyCXKW+w=="
        )

        otk = "T1RLAQK9THj0okLTUB663QrJFg5qA58IDhAb93ondvcx7sY6s44" \
              "eszNqAAAga5W8Dc4XZwtsZ4qV3_lDI-Zn2_yadHHIhkGqNV5J9kw*"
        payload = _token.decode(otk, 2)
        expected_payload = self.canonical_payload
        assert payload == expected_payload

    @patch("opentoken._token.get_random_bytes")
    @patch("opentoken._ciphersuite.generate_key")
    def test_encode_aes_128_canonical(self, encryption_key_mock, iv_mock):
        encryption_key_mock.return_value = base64.standard_b64decode(
            "a66C9MvM8eY4qJKyCXKW+w=="
        )
        iv_mock.return_value = bytearray(
            b"\x1b\xf7z\'v\xf71\xee\xc6:\xb3\x8e\x1e\xb33j"
        )

        otk = _token.encode(self.canonical_payload, 2)
        expected_otk = "T1RLAQK9THj0okLTUB663QrJFg5qA58IDhAb93ondvcx7sY6s44" \
                       "eszNqAAAga5W8Dc4XZwtsZ4qV3_lDI-Zn2_yadHHIhkGqNV5J9kw*"
        assert otk == expected_otk

    @patch("opentoken._ciphersuite.generate_key")
    def test_decode_aes_256_canonical(self, decryption_key_mock):
        decryption_key_mock.return_value = base64.standard_b64decode(
            "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc="
        )

        otk = "T1RLAQEujlLGEvmVKDKyvL1vaZ27qMYhTxDSAZwtaufqUff7GQXTjv" \
              "WBAAAgJJGPta7VOITap4uDZ_OkW_Kt4yYZ4BBQzw_NR2CNE-g*"
        payload = _token.decode(otk, 1)
        expected_payload = OrderedDict([
            ("foo", "bar"),
            ("bar", "baz"),
        ])
        assert payload == expected_payload

    @patch("opentoken._token.get_random_bytes")
    @patch("opentoken._ciphersuite.generate_key")
    def test_encode_aes_256_canonical(self, encryption_key_mock, iv_mock):
        encryption_key_mock.return_value = base64.standard_b64decode(
            "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc="
        )
        iv_mock.return_value = bytearray(
            b'\xd2\x01\x9c-j\xe7\xeaQ\xf7\xfb\x19\x05\xd3\x8e\xf5\x81'
        )

        otk = _token.encode(self.canonical_payload, 1)
        expected_otk = "T1RLAQEujlLGEvmVKDKyvL1vaZ27qMYhTxDSAZwtaufq" \
                       "Uff7GQXTjvWBAAAgJJGPta7VOITap4uDZ" \
                       "_OkW_Kt4yYZ4BBQzw_NR2CNE-g*"
        assert otk == expected_otk

    @patch("opentoken._ciphersuite.generate_key")
    def test_decode_3des_168_canonical(self, decryption_key_mock):
        decryption_key_mock.return_value = base64.standard_b64decode(
            "a66C9MvM8eY4qJKyCXKW+19PWDeuc3th"
        )

        otk = "T1RLAQNoCsuAwybXOSBpIc9ZvxQVx_3fhghqSjy-" \
              "pNJpfgAAGGlGgJ79NhX43lLRXAb9Mp5unR7XFWopzw**"
        payload = _token.decode(otk, 3)
        expected_payload = OrderedDict([
            ("foo", "bar"),
            ("bar", "baz"),
        ])
        assert payload == expected_payload

    @patch("opentoken._token.get_random_bytes")
    @patch("opentoken._ciphersuite.generate_key")
    def test_encode_aes_256_canonical(self, encryption_key_mock, iv_mock):
        encryption_key_mock.return_value = base64.standard_b64decode(
            "a66C9MvM8eY4qJKyCXKW+19PWDeuc3th"
        )
        iv_mock.return_value = bytearray(
            b'jJ<\xbe\xa4\xd2i~'
        )

        otk = _token.encode(self.canonical_payload, 3)
        expected_otk = "T1RLAQNoCsuAwybXOSBpIc9ZvxQVx_3fhghqSjy-" \
                       "pNJpfgAAGGlGgJ79NhX43lLRXAb9Mp5unR7XFWopzw**"
        assert otk == expected_otk
