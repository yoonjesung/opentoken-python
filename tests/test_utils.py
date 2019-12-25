"""Unit tests for _utils.py
"""

import json
from collections import OrderedDict

import pytest

from opentoken import _utils


class TestValidations:
    def test_cipher_suite_validations(self):
        with pytest.raises(TypeError):
            _utils.validate_cipher_suite_id("3")
        with pytest.raises(ValueError):
            _utils.validate_cipher_suite_id(4)
        with pytest.raises(ValueError):
            _utils.validate_cipher_suite_id(-1)

    def test_password_validations(self):
        with pytest.raises(TypeError):
            _utils.validate_password(3)
        assert isinstance(_utils.validate_password("123"), str) is True
        assert isinstance(_utils.validate_password(b"123"), bytes) is True
        assert isinstance(_utils.validate_password(None), str) is True

    def test_payload_validations(self):
        with pytest.raises(TypeError):
            _utils.validate_payload({1: 2})
        test_dict = OrderedDict([("b", 2), ("a", 1)])
        assert _utils.validate_payload(
            json.dumps(test_dict)
        ) == test_dict
        assert _utils.validate_payload(test_dict) == test_dict

    def test_reformat_to_otk_b64(self):
        assert _utils.reformat_to_otk_b64("a=bc") == "a=bc"
        assert _utils.reformat_to_otk_b64("a=bc=") == "a=bc*"
        assert _utils.reformat_to_otk_b64("a=bc==") == "a=bc**"

    def test_reformat_from_otk_b64(self):
        assert _utils.reformat_from_otk_b64("a=bc") == "a=bc"
        assert _utils.reformat_from_otk_b64("a=bc*") == "a=bc="
        assert _utils.reformat_from_otk_b64("a=bc**") == "a=bc=="

    def test_ordered_dict_to_otk_str(self):
        od = _utils.ordered_dict_to_otk_str(OrderedDict([
            ("key1", "val1"),
            ("key2", "val2"),
            (3, "v3"),
        ]))
        assert od == "key1=val1\nkey2=val2\n3=v3"
