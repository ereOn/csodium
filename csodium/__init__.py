"""
A standalone Python interface for libsodium.
"""

import six

from ._impl import (
    ffi,
    lib,
)

if lib.sodium_init() < 0:
    raise RuntimeError("libsodium initialization failed")


def randombytes(size):
    buf = bytearray(size)
    lib.randombytes(ffi.from_buffer(buf), size)
    return six.binary_type(buf)
