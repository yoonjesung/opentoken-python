"""Unit tests for token.py
"""

from __future__ import absolute_import

import pytest

from opentoken import validations


class TestValidations:
    def test_cipher_suite_validations(self):
        with pytest.raises(TypeError):
            validations.validate_cipher_suite_id("3")
        with pytest.raises(ValueError):
            validations.validate_cipher_suite_id(4)
        with pytest.raises(ValueError):
            validations.validate_cipher_suite_id(-1)

    def test_password_validations(self):
        with pytest.raises(TypeError):
            validations.validate_password(3)
        assert isinstance(validations.validate_password("123"), bytes) is True
        assert isinstance(validations.validate_password(b"123"), bytes) is True
        assert isinstance(validations.validate_password(None), bytes) is True
