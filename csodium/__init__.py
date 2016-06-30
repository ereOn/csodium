"""
A standalone Python interface for libsodium.
"""

from six import binary_type

from ._impl import (
    ffi,
    lib,
)

if lib.sodium_init() < 0:  # pragma: no cover
    raise RuntimeError("libsodium initialization failed")


SODIUM_VERSION_STRING = ffi.string(lib.sodium_version_string()).decode('utf-8')
SODIUM_VERSION = tuple(map(int, SODIUM_VERSION_STRING.split('.')))


def _raise_on_error(return_code):
    if return_code != 0:
        raise ValueError("Call returned %s" % return_code)


def _assert_len(name, buf, size):
    assert buf, "%s cannot be NULL" % name
    assert len(buf) == size, "%s must be %d byte(s) long" % (name, size)


# random family.
def randombytes(size):
    buf = bytearray(size)
    lib.randombytes(ffi.from_buffer(buf), size)
    return binary_type(buf)


# crypto_box family.
crypto_box_BEFORENMBYTES = lib.crypto_box_beforenmbytes()
crypto_box_MACBYTES = lib.crypto_box_macbytes()
crypto_box_NONCEBYTES = lib.crypto_box_noncebytes()
crypto_box_PUBLICKEYBYTES = lib.crypto_box_publickeybytes()
crypto_box_SEALBYTES = lib.crypto_box_sealbytes()
crypto_box_SECRETKEYBYTES = lib.crypto_box_secretkeybytes()
crypto_box_SEEDBYTES = lib.crypto_box_seedbytes()


def crypto_box_keypair():
    pk = bytearray(crypto_box_PUBLICKEYBYTES)
    sk = bytearray(crypto_box_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_box_keypair(
            ffi.from_buffer(pk),
            ffi.from_buffer(sk),
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_box_seed_keypair(seed):
    _assert_len('seed', seed, crypto_box_SEEDBYTES)

    pk = bytearray(crypto_box_PUBLICKEYBYTES)
    sk = bytearray(crypto_box_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_box_seed_keypair(
            ffi.from_buffer(pk),
            ffi.from_buffer(sk),
            seed,
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_box_beforenm(pk, sk):
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    k = bytearray(crypto_box_BEFORENMBYTES)
    _raise_on_error(
        lib.crypto_box_beforenm(
            ffi.from_buffer(k),
            pk,
            sk,
        ),
    )

    return binary_type(k)


def crypto_box(msg, nonce, pk, sk):
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    c = bytearray(crypto_box_MACBYTES + len(msg))
    _raise_on_error(
        lib.crypto_box_easy(
            ffi.from_buffer(c),
            msg,
            len(msg),
            nonce,
            pk,
            sk,
        ),
    )

    return binary_type(c)


def crypto_box_afternm(msg, nonce, k):
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('k', k, crypto_box_BEFORENMBYTES)

    c = bytearray(crypto_box_MACBYTES + len(msg))
    _raise_on_error(
        lib.crypto_box_easy_afternm(
            ffi.from_buffer(c),
            msg,
            len(msg),
            nonce,
            k,
        ),
    )

    return binary_type(c)


def crypto_box_open(c, nonce, pk, sk):
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    msg = bytearray(len(c) - crypto_box_MACBYTES)
    _raise_on_error(
        lib.crypto_box_open_easy(
            ffi.from_buffer(msg),
            c,
            len(c),
            nonce,
            pk,
            sk,
        ),
    )

    return binary_type(msg)


def crypto_box_open_afternm(c, nonce, k):
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('k', k, crypto_box_BEFORENMBYTES)

    msg = bytearray(len(c) - crypto_box_MACBYTES)
    _raise_on_error(
        lib.crypto_box_open_easy_afternm(
            ffi.from_buffer(msg),
            c,
            len(c),
            nonce,
            k,
        ),
    )

    return binary_type(msg)


def crypto_box_seal(msg, pk):
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)

    c = bytearray(len(msg) + crypto_box_SEALBYTES)
    _raise_on_error(
        lib.crypto_box_seal(
            ffi.from_buffer(c),
            msg,
            len(msg),
            pk,
        ),
    )

    return binary_type(c)


def crypto_box_seal_open(c, pk, sk):
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    msg = bytearray(len(c) - crypto_box_SEALBYTES)
    _raise_on_error(
        lib.crypto_box_seal_open(
            ffi.from_buffer(msg),
            c,
            len(c),
            pk,
            sk,
        ),
    )

    return binary_type(msg)


def crypto_box_detached(msg, nonce, pk, sk):
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    c = bytearray(len(msg))
    mac = bytearray(crypto_box_MACBYTES)
    _raise_on_error(
        lib.crypto_box_detached(
            ffi.from_buffer(c),
            ffi.from_buffer(mac),
            msg,
            len(msg),
            nonce,
            pk,
            sk,
        ),
    )

    return binary_type(c), binary_type(mac)


def crypto_box_open_detached(c, mac, nonce, pk, sk):
    _assert_len('mac', mac, crypto_box_MACBYTES)
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    msg = bytearray(len(c))
    _raise_on_error(
        lib.crypto_box_open_detached(
            ffi.from_buffer(msg),
            c,
            mac,
            len(c),
            nonce,
            pk,
            sk,
        ),
    )

    return binary_type(msg)


# crypto_secretbox family.
crypto_secretbox_KEYBYTES = lib.crypto_secretbox_keybytes()
crypto_secretbox_NONCEBYTES = lib.crypto_secretbox_noncebytes()
crypto_secretbox_MACBYTES = lib.crypto_secretbox_macbytes()


def crypto_secretbox(msg, nonce, k):
    _assert_len('nonce', nonce, crypto_secretbox_NONCEBYTES)
    _assert_len('k', k, crypto_secretbox_KEYBYTES)

    c = bytearray(crypto_secretbox_MACBYTES + len(msg))
    _raise_on_error(
        lib.crypto_secretbox_easy(
            ffi.from_buffer(c),
            msg,
            len(msg),
            nonce,
            k,
        ),
    )

    return binary_type(c)


def crypto_secretbox_open(c, nonce, k):
    _assert_len('nonce', nonce, crypto_secretbox_NONCEBYTES)
    _assert_len('k', k, crypto_secretbox_KEYBYTES)

    msg = bytearray(len(c) - crypto_secretbox_MACBYTES)
    _raise_on_error(
        lib.crypto_secretbox_open_easy(
            ffi.from_buffer(msg),
            c,
            len(c),
            nonce,
            k,
        ),
    )

    return binary_type(msg)
