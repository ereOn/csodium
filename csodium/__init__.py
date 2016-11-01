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


def _assert_len(name, buf, size, max_size=None):
    assert buf, "%s cannot be NULL" % name

    if max_size:
        assert size <= len(buf) <= max_size, (
            "%s must be between %d and %d bytes long" % (name, size, max_size)
        )
    else:
        assert len(buf) == size, "%s must be %d byte(s) long" % (name, size)


def _assert_min_len(name, buf, min_size):
    assert buf, "%s cannot be NULL" % name

    assert min_size <= len(buf), (
            "%s must be at least %d bytes long" % (name, min_size)
        )


# random family.
def randombytes(size):
    buf = bytearray(size)
    lib.randombytes(ffi.cast("unsigned char *", ffi.from_buffer(buf)), size)
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
            ffi.cast("unsigned char *", ffi.from_buffer(pk)),
            ffi.cast("unsigned char *", ffi.from_buffer(sk)),
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_box_seed_keypair(seed):
    _assert_len('seed', seed, crypto_box_SEEDBYTES)

    pk = bytearray(crypto_box_PUBLICKEYBYTES)
    sk = bytearray(crypto_box_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_box_seed_keypair(
            ffi.cast("unsigned char *", ffi.from_buffer(pk)),
            ffi.cast("unsigned char *", ffi.from_buffer(sk)),
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
            ffi.cast("unsigned char *", ffi.from_buffer(k)),
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
            ffi.cast("unsigned char *", ffi.from_buffer(c)),
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
            ffi.cast("unsigned char *", ffi.from_buffer(c)),
            msg,
            len(msg),
            nonce,
            k,
        ),
    )

    return binary_type(c)


def crypto_box_open(c, nonce, pk, sk):
    _assert_min_len('c', c, crypto_box_MACBYTES)
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    msg = bytearray(len(c) - crypto_box_MACBYTES)
    _raise_on_error(
        lib.crypto_box_open_easy(
            ffi.cast("unsigned char *", ffi.from_buffer(msg)),
            c,
            len(c),
            nonce,
            pk,
            sk,
        ),
    )

    return binary_type(msg)


def crypto_box_open_afternm(c, nonce, k):
    _assert_min_len('c', c, crypto_box_MACBYTES)
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('k', k, crypto_box_BEFORENMBYTES)

    msg = bytearray(len(c) - crypto_box_MACBYTES)
    _raise_on_error(
        lib.crypto_box_open_easy_afternm(
            ffi.cast("unsigned char *", ffi.from_buffer(msg)),
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
            ffi.cast("unsigned char *", ffi.from_buffer(c)),
            msg,
            len(msg),
            pk,
        ),
    )

    return binary_type(c)


def crypto_box_seal_open(c, pk, sk):
    _assert_min_len('c', c, crypto_box_SEALBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    msg = bytearray(len(c) - crypto_box_SEALBYTES)
    _raise_on_error(
        lib.crypto_box_seal_open(
            ffi.cast("unsigned char *", ffi.from_buffer(msg)),
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
            ffi.cast("unsigned char *", ffi.from_buffer(c)),
            ffi.cast("unsigned char *", ffi.from_buffer(mac)),
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
            ffi.cast("unsigned char *", ffi.from_buffer(msg)),
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
            ffi.cast("unsigned char *", ffi.from_buffer(c)),
            msg,
            len(msg),
            nonce,
            k,
        ),
    )

    return binary_type(c)


def crypto_secretbox_open(c, nonce, k):
    _assert_min_len('c', c, crypto_secretbox_MACBYTES)
    _assert_len('nonce', nonce, crypto_secretbox_NONCEBYTES)
    _assert_len('k', k, crypto_secretbox_KEYBYTES)

    msg = bytearray(len(c) - crypto_secretbox_MACBYTES)
    _raise_on_error(
        lib.crypto_secretbox_open_easy(
            ffi.cast("unsigned char *", ffi.from_buffer(msg)),
            c,
            len(c),
            nonce,
            k,
        ),
    )

    return binary_type(msg)


crypto_generichash_blake2b_BYTES_MIN = \
    lib.crypto_generichash_blake2b_bytes_min()
crypto_generichash_blake2b_BYTES_MAX = \
    lib.crypto_generichash_blake2b_bytes_max()
crypto_generichash_blake2b_BYTES = lib.crypto_generichash_blake2b_bytes()
crypto_generichash_blake2b_KEYBYTES_MIN = \
    lib.crypto_generichash_blake2b_keybytes_min()
crypto_generichash_blake2b_KEYBYTES_MAX = \
    lib.crypto_generichash_blake2b_keybytes_max()
crypto_generichash_blake2b_KEYBYTES = lib.crypto_generichash_blake2b_keybytes()
crypto_generichash_blake2b_SALTBYTES = \
    lib.crypto_generichash_blake2b_saltbytes()
crypto_generichash_blake2b_PERSONALBYTES = \
    lib.crypto_generichash_blake2b_personalbytes()


def crypto_generichash_blake2b_salt_personal(
    in_,
    key,
    salt,
    personal=None,
    outlen=crypto_generichash_blake2b_BYTES_MAX,
):
    _assert_len(
        'key',
        key,
        crypto_generichash_blake2b_KEYBYTES_MIN,
        crypto_generichash_blake2b_KEYBYTES_MAX,
    )
    _assert_len('salt', salt, crypto_generichash_blake2b_SALTBYTES)

    if personal is not None:
        _assert_len(
            'personal',
            personal,
            crypto_generichash_blake2b_PERSONALBYTES,
        )

    assert crypto_generichash_blake2b_BYTES_MIN <= outlen <= \
        crypto_generichash_blake2b_BYTES_MAX, (
            "outlen must be between %d and %d" % (
                crypto_generichash_blake2b_BYTES_MIN,
                crypto_generichash_blake2b_BYTES_MAX,
            )
        )

    buf = bytearray(outlen)

    _raise_on_error(
        lib.crypto_generichash_blake2b_salt_personal(
            ffi.cast('uint8_t *', ffi.from_buffer(buf)),
            outlen,
            in_ if in_ is not None else ffi.NULL,
            len(in_ or ()),
            key,
            len(key),
            salt,
            personal if personal is not None else ffi.NULL,
        ),
    )
    return binary_type(buf)

# crypto_sign family
crypto_sign_BYTES = lib.crypto_sign_bytes()
crypto_sign_SEEDBYTES = lib.crypto_sign_seedbytes()
crypto_sign_PUBLICKEYBYTES = lib.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = lib.crypto_sign_secretkeybytes()


def crypto_sign_keypair():
    pk = bytearray(crypto_sign_PUBLICKEYBYTES)
    sk = bytearray(crypto_sign_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_sign_keypair(
            ffi.cast("unsigned char *", ffi.from_buffer(pk)),
            ffi.cast("unsigned char *", ffi.from_buffer(sk)),
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_sign_seed_keypair(seed):
    _assert_len('seed', seed, crypto_sign_SEEDBYTES)

    pk = bytearray(crypto_sign_PUBLICKEYBYTES)
    sk = bytearray(crypto_sign_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_sign_seed_keypair(
            ffi.cast("unsigned char *", ffi.from_buffer(pk)),
            ffi.cast("unsigned char *", ffi.from_buffer(sk)),
            seed,
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_sign(msg, sk):
    _assert_len('sk', sk, crypto_sign_SECRETKEYBYTES)

    signed_msg = bytearray(crypto_sign_BYTES + len(msg))
    _raise_on_error(
        lib.crypto_sign(
            ffi.cast("unsigned char *", ffi.from_buffer(signed_msg)),
            ffi.NULL,
            msg,
            len(msg),
            sk,
        ),
    )

    return binary_type(signed_msg)


def crypto_sign_open(signed_msg, pk):
    _assert_min_len('signed_msg', signed_msg, crypto_sign_BYTES)
    _assert_len('pk', pk, crypto_sign_PUBLICKEYBYTES)

    msg = bytearray(len(signed_msg) - crypto_sign_BYTES)
    _raise_on_error(
        lib.crypto_sign_open(
            ffi.cast("unsigned char *", ffi.from_buffer(msg)),
            ffi.NULL,
            signed_msg,
            len(signed_msg),
            pk,
        ),
    )

    return binary_type(msg)


def crypto_sign_detached(msg, sk):
    _assert_len('sk', sk, crypto_sign_SECRETKEYBYTES)

    sig = bytearray(crypto_sign_BYTES)
    _raise_on_error(
        lib.crypto_sign_detached(
            ffi.cast("unsigned char *", ffi.from_buffer(sig)),
            ffi.NULL,
            msg,
            len(msg),
            sk,
        ),
    )

    return binary_type(sig)


def crypto_sign_verify_detached(msg, sig, pk):
    _assert_len('sig', sig, crypto_sign_BYTES)
    _assert_len('pk', pk, crypto_sign_PUBLICKEYBYTES)

    _raise_on_error(
        lib.crypto_sign_verify_detached(
            sig,
            msg,
            len(msg),
            pk,
        ),
    )

    return True


# ed25519 sign specific functions
crypto_sign_ed25519_SEEDBYTES = lib.crypto_sign_ed25519_seedbytes()
crypto_sign_ed25519_PUBLICKEYBYTES = lib.crypto_sign_ed25519_publickeybytes()
crypto_sign_ed25519_SECRETKEYBYTES = lib.crypto_sign_ed25519_secretkeybytes()
crypto_scalarmult_curve25519_BYTES = lib.crypto_scalarmult_curve25519_bytes()


def crypto_sign_ed25519_pk_to_curve25519(ed25519_pk):
    _assert_len("ed25519_pk", ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES)
    curve25519_pk = bytearray(crypto_scalarmult_curve25519_BYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_pk_to_curve25519(
            ffi.cast("unsigned char *", ffi.from_buffer(curve25519_pk)),
            ffi.cast("unsigned char *", ffi.from_buffer(ed25519_pk)),
        ),
    )

    return binary_type(curve25519_pk)


def crypto_sign_ed25519_sk_to_curve25519(ed25519_sk):
    _assert_len("ed25519_sk", ed25519_sk, crypto_sign_ed25519_SECRETKEYBYTES)
    curve25519_sk = bytearray(crypto_scalarmult_curve25519_BYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_sk_to_curve25519(
            ffi.cast("unsigned char *", ffi.from_buffer(curve25519_sk)),
            ffi.cast("unsigned char *", ffi.from_buffer(ed25519_sk)),
        ),
    )

    return binary_type(curve25519_sk)


def crypto_sign_ed25519_sk_to_seed(sk):
    _assert_len("sk", sk, crypto_sign_ed25519_SECRETKEYBYTES)
    seed = bytearray(crypto_sign_ed25519_SEEDBYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_sk_to_seed(
            ffi.cast("unsigned char *", ffi.from_buffer(seed)),
            sk,
        ),
    )

    return binary_type(seed)


def crypto_sign_ed25519_sk_to_pk(sk):
    _assert_len("sk", sk, crypto_sign_ed25519_SECRETKEYBYTES)
    pk = bytearray(crypto_sign_ed25519_PUBLICKEYBYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_sk_to_pk(
            ffi.cast("unsigned char *", ffi.from_buffer(pk)),
            sk,
        ),
    )

    return binary_type(pk)
