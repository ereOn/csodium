"""
A standalone Python interface for libsodium.
"""

import six

from ._impl import (
    ffi,
    lib,
)

if lib.sodium_init() < 0:  # pragma: no cover
    raise RuntimeError("libsodium initialization failed")


def randombytes(size):
    buf = bytearray(size)
    lib.randombytes(ffi.from_buffer(buf), size)
    return six.binary_type(buf)


SODIUM_VERSION_STRING = ffi.string(lib.sodium_version_string()).decode('utf-8')
SODIUM_VERSION = tuple(map(int, SODIUM_VERSION_STRING.split('.')))
