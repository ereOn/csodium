"""
Test the whole exposed API.
"""

from csodium import (
    SODIUM_VERSION,
    randombytes,
)


def test_version():
    # There is nothing much we can test here.
    assert len(SODIUM_VERSION) == 3

    for x in SODIUM_VERSION:
        assert isinstance(x, int)


def test_randombytes():
    b = randombytes(4)
    assert len(b) == 4
