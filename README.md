# opentoken-python

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](code-of-conduct.md)

OpenToken support for Python.

A Python implementation of generating and parsing OpenTokens. Much of this implementation is borrowed from [node-opentoken](https://github.com/73rhodes/node-opentoken).

https://tools.ietf.org/html/draft-smith-opentoken-02

## Usage

### Create an opentoken string:

```
from opentoken import OpenToken

otkapi = OpenToken("your_password")
otkapi.create_token([
    ("subject", "foobar"),
    ("key2", "val2")
])
```

### Parse an opentoken string:

```
otkapi = OpenToken("your_password")
otkapi.parse_token("your_base64_encoded_token_string")
```

### OpenToken constructor

`password`: Defaults to None.

`cipher_suite_id`: Defaults to 2. Possible ids are 0 - no encryption, 1 - AES-256, 2 - AES-128, and 3 - 3DES-168.

`token_tolerance`: Defaults to 120 seconds.

`token_lifetime`: Defaults to 300 seconds.

`token_renewal`: Defaults to 12 hours.

## Contributing

Feel free to dive in! [Open an issue](https://github.com/yoonjesung/opentoken-python/issues/new) or submit PRs.
