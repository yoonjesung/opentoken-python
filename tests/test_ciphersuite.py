"""Unit tests for _ciphersuite.py
"""

from opentoken import _ciphersuite


class TestCipherSuite:
    def test_generate_key_len(self):
        derived_key = _ciphersuite.generate_key("", 1)
        assert len(derived_key) == 32
        derived_key = _ciphersuite.generate_key("", 2)
        assert len(derived_key) == 16
        derived_key = _ciphersuite.generate_key("", 3)
        assert len(derived_key) == 21

    def test_cipher_suite_0(self):
        derived_key = _ciphersuite.generate_key("", 0)
        assert derived_key is None
