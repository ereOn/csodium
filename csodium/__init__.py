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


SODIUM_VERSION_STRING = ffi.string(lib.sodium_version_string()).decode('utf-8')
SODIUM_VERSION = tuple(map(int, SODIUM_VERSION_STRING.split('.')))


# random family.
def randombytes(size):
    buf = bytearray(size)
    lib.randombytes(ffi.from_buffer(buf), size)
    return six.binary_type(buf)


# crypto_box family.
crypto_box_BOXZEROBYTES = lib.crypto_box_boxzerobytes()
crypto_box_MACBYTES = lib.crypto_box_macbytes()
crypto_box_NONCEBYTES = lib.crypto_box_noncebytes()
crypto_box_PUBLICKEYBYTES = lib.crypto_box_publickeybytes()
crypto_box_SEALBYTES = lib.crypto_box_sealbytes()
crypto_box_SECRETKEYBYTES = lib.crypto_box_secretkeybytes()
crypto_box_SEEDBYTES = lib.crypto_box_seedbytes()
crypto_box_ZEROBYTES = lib.crypto_box_zerobytes()
