"""Unit tests for utils.py
"""

import json
from collections import OrderedDict

import pytest

from opentoken import utils


class TestValidations:
    def test_cipher_suite_validations(self):
        with pytest.raises(TypeError):
            utils.validate_cipher_suite_id("3")
        with pytest.raises(ValueError):
            utils.validate_cipher_suite_id(4)
        with pytest.raises(ValueError):
            utils.validate_cipher_suite_id(-1)

    def test_password_validations(self):
        with pytest.raises(TypeError):
            utils.validate_password(3)
        assert isinstance(utils.validate_password("123"), str) is True
        assert isinstance(utils.validate_password(b"123"), bytes) is True
        assert isinstance(utils.validate_password(None), str) is True

    def test_payload_validations(self):
        with pytest.raises(TypeError):
            utils.validate_payload({1: 2})
        test_dict = OrderedDict([("b", 2), ("a", 1)])
        assert utils.validate_payload(
            json.dumps(test_dict)
        ) == test_dict
        assert utils.validate_payload(test_dict) == test_dict

    def test_reformat_to_otk_b64(self):
        assert utils.reformat_to_otk_b64("a=bc") == "a=bc"
        assert utils.reformat_to_otk_b64("a=bc=") == "a=bc*"
        assert utils.reformat_to_otk_b64("a=bc==") == "a=bc**"

    def test_reformat_from_otk_b64(self):
        assert utils.reformat_from_otk_b64("a=bc") == "a=bc"
        assert utils.reformat_from_otk_b64("a=bc*") == "a=bc="
        assert utils.reformat_from_otk_b64("a=bc**") == "a=bc=="

    def test_ordered_dict_to_otk_str(self):
        od = utils.ordered_dict_to_otk_str(OrderedDict([
            ("key1", "val1"),
            ("key2", "val2"),
            (3, "v3"),
        ]))
        assert od == "key1=val1\nkey2=val2\n3=v3"
