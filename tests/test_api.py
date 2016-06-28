"""
Test the whole exposed API.
"""

from csodium import (
    randombytes,
)


def test_randombytes():
    b = randombytes(4)
    assert len(b) == 4
