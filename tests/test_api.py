"""
Test the whole exposed API.
"""

import pytest

from six import binary_type

from csodium import (
    SODIUM_VERSION,
    crypto_box,
    crypto_box_BEFORENMBYTES,
    crypto_box_MACBYTES,
    crypto_box_NONCEBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_SEEDBYTES,
    crypto_box_afternm,
    crypto_box_beforenm,
    crypto_box_detached,
    crypto_box_keypair,
    crypto_box_open,
    crypto_box_open_afternm,
    crypto_box_open_detached,
    crypto_box_seal,
    crypto_box_seal_open,
    crypto_box_seed_keypair,
    crypto_secretbox,
    crypto_secretbox_open,
    randombytes,
    crypto_generichash_blake2b_KEYBYTES,
    crypto_generichash_blake2b_SALTBYTES,
    crypto_generichash_blake2b_PERSONALBYTES,
    crypto_generichash_blake2b_salt_personal,
)


@pytest.fixture
def pk():
    pk, _ = crypto_box_seed_keypair(b'x' * crypto_box_SEEDBYTES)
    return pk


@pytest.fixture
def sk():
    _, sk = crypto_box_seed_keypair(b'x' * crypto_box_SEEDBYTES)
    return sk


@pytest.fixture
def nonce():
    return b'x' * crypto_box_NONCEBYTES


@pytest.fixture
def k(pk, sk):
    return crypto_box_beforenm(pk=pk, sk=sk)


@pytest.fixture
def mac():
    return b'x' * crypto_box_MACBYTES


@pytest.fixture
def key():
    return b'x' * crypto_generichash_blake2b_KEYBYTES


@pytest.fixture
def salt():
    return b'x' * crypto_generichash_blake2b_SALTBYTES


@pytest.fixture
def personal():
    return b'x' * crypto_generichash_blake2b_PERSONALBYTES


def test_version():
    # There is nothing much we can test here.
    assert len(SODIUM_VERSION) == 3

    for x in SODIUM_VERSION:
        assert isinstance(x, int)


def test_randombytes():
    b = randombytes(4)
    assert len(b) == 4


def test_crypto_box_keypair():
    pk, sk = crypto_box_keypair()
    assert len(pk) == crypto_box_PUBLICKEYBYTES
    assert len(sk) == crypto_box_SECRETKEYBYTES


def test_crypto_box_seed_keypair_invalid_seed():
    with pytest.raises(AssertionError):
        crypto_box_seed_keypair(b'invalid')


def test_crypto_box_seed_keypair():
    pk, sk = crypto_box_seed_keypair(b'x' * crypto_box_SEEDBYTES)
    assert len(pk) == crypto_box_PUBLICKEYBYTES
    assert len(sk) == crypto_box_SECRETKEYBYTES


def test_crypto_box_beforenm_invalid_pk(sk):
    with pytest.raises(AssertionError):
        crypto_box_beforenm(
            pk=b'',
            sk=sk,
        )


def test_crypto_box_beforenm_invalid_sk(pk):
    with pytest.raises(AssertionError):
        crypto_box_beforenm(
            pk=pk,
            sk=b'',
        )


def test_crypto_box_beforenm(pk, sk):
    k = crypto_box_beforenm(
        pk=pk,
        sk=sk,
    )
    assert len(k) == crypto_box_BEFORENMBYTES


def test_crypto_box_invalid_nonce(pk, sk):
    with pytest.raises(AssertionError):
        crypto_box(
            msg=b'foo',
            nonce=b'',
            pk=pk,
            sk=sk,
        )


def test_crypto_box_invalid_pk(nonce, sk):
    with pytest.raises(AssertionError):
        crypto_box(
            msg=b'foo',
            nonce=nonce,
            pk=b'',
            sk=sk,
        )


def test_crypto_box_invalid_sk(nonce, pk):
    with pytest.raises(AssertionError):
        crypto_box(
            msg=b'foo',
            nonce=nonce,
            pk=pk,
            sk=b'',
        )


def test_crypto_box(nonce, pk, sk):
    c = crypto_box(
        msg=b'foo',
        nonce=nonce,
        pk=pk,
        sk=sk,
    )
    assert isinstance(c, binary_type)


def test_crypto_box_afternm_invalid_nonce(k):
    with pytest.raises(AssertionError):
        crypto_box_afternm(
            msg=b'foo',
            nonce=b'',
            k=k,
        )


def test_crypto_box_afternm_invalid_k(nonce):
    with pytest.raises(AssertionError):
        crypto_box_afternm(
            msg=b'foo',
            nonce=nonce,
            k=b'',
        )


def test_crypto_box_afternm(nonce, k):
    c = crypto_box_afternm(
        msg=b'foo',
        nonce=nonce,
        k=k,
    )
    assert isinstance(c, binary_type)


def test_crypto_box_open_invalid_nonce(pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_open(
            c=b'x' * 100,
            nonce=b'',
            pk=pk,
            sk=sk,
        )


def test_crypto_box_open_invalid_pk(nonce, sk):
    with pytest.raises(AssertionError):
        crypto_box_open(
            c=b'x' * 100,
            nonce=nonce,
            pk=b'',
            sk=sk,
        )


def test_crypto_box_open_invalid_sk(nonce, pk):
    with pytest.raises(AssertionError):
        crypto_box_open(
            c=b'x' * 100,
            nonce=nonce,
            pk=pk,
            sk=b'',
        )


def test_crypto_box_open_failure(nonce, pk, sk):
    with pytest.raises(ValueError):
        crypto_box_open(
            c=b'x' * 100,
            nonce=nonce,
            pk=pk,
            sk=sk,
        )


def test_crypto_box_open(nonce, pk, sk):
    c = crypto_box(
        msg=b'foo',
        nonce=nonce,
        pk=pk,
        sk=sk,
    )
    msg = crypto_box_open(
        c=c,
        nonce=nonce,
        pk=pk,
        sk=sk,
    )
    assert msg == b'foo'


def test_crypto_box_open_afternm_invalid_nonce(k):
    with pytest.raises(AssertionError):
        crypto_box_open_afternm(
            c=b'x' * 100,
            nonce=b'',
            k=k,
        )


def test_crypto_box_open_afternm_invalid_k(nonce):
    with pytest.raises(AssertionError):
        crypto_box_open_afternm(
            c=b'x' * 100,
            nonce=nonce,
            k=b'',
        )


def test_crypto_box_open_afternm(nonce, k):
    c = crypto_box_afternm(
        msg=b'foo',
        nonce=nonce,
        k=k,
    )
    msg = crypto_box_open_afternm(
        c=c,
        nonce=nonce,
        k=k,
    )
    assert msg == b'foo'


def test_crypto_box_seal_invalid_pk():
    with pytest.raises(AssertionError):
        crypto_box_seal(
            msg=b'foo',
            pk=b'',
        )


def test_crypto_box_seal(pk):
    c = crypto_box_seal(
        msg=b'foo',
        pk=pk,
    )
    assert isinstance(c, binary_type)


def test_crypto_box_seal_open_invalid_pk(sk):
    with pytest.raises(AssertionError):
        crypto_box_seal_open(
            c=b'',
            pk=b'',
            sk=sk,
        )


def test_crypto_box_seal_open_invalid_sk(pk):
    with pytest.raises(AssertionError):
        crypto_box_seal_open(
            c=b'',
            pk=pk,
            sk=b'',
        )


def test_crypto_box_seal_open(pk, sk):
    c = crypto_box_seal(
        msg=b'foo',
        pk=pk,
    )
    msg = crypto_box_seal_open(
        c=c,
        pk=pk,
        sk=sk,
    )
    assert msg == b'foo'


def test_crypto_box_detached_invalid_nonce(pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_detached(
            msg=b'foo',
            nonce=b'',
            pk=pk,
            sk=sk,
        )


def test_crypto_box_detached_invalid_pk(nonce, sk):
    with pytest.raises(AssertionError):
        crypto_box_detached(
            msg=b'foo',
            nonce=nonce,
            pk=b'',
            sk=sk,
        )


def test_crypto_box_detached_invalid_sk(nonce, pk):
    with pytest.raises(AssertionError):
        crypto_box_detached(
            msg=b'foo',
            nonce=nonce,
            pk=pk,
            sk=b'',
        )


def test_crypto_box_detached(nonce, pk, sk):
    c, mac = crypto_box_detached(
        msg=b'foo',
        nonce=nonce,
        pk=pk,
        sk=sk,
    )
    assert isinstance(c, binary_type)
    assert isinstance(mac, binary_type)


def test_crypto_box_open_detached_invalid_mac(nonce, pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_open_detached(
            c=b'',
            mac=b'',
            nonce=nonce,
            pk=pk,
            sk=sk,
        )


def test_crypto_box_open_detached_invalid_nonce(mac, pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_open_detached(
            c=b'',
            mac=mac,
            nonce=b'',
            pk=pk,
            sk=sk,
        )


def test_crypto_box_open_detached_invalid_pk(mac, nonce, sk):
    with pytest.raises(AssertionError):
        crypto_box_open_detached(
            c=b'',
            mac=mac,
            nonce=nonce,
            pk=b'',
            sk=sk,
        )


def test_crypto_box_open_detached_invalid_sk(mac, nonce, pk):
    with pytest.raises(AssertionError):
        crypto_box_open_detached(
            c=b'',
            mac=mac,
            nonce=nonce,
            pk=pk,
            sk=b'',
        )


def test_crypto_box_open_detached(nonce, pk, sk):
    c, mac = crypto_box_detached(
        msg=b'foo',
        nonce=nonce,
        pk=pk,
        sk=sk,
    )
    msg = crypto_box_open_detached(
        c=c,
        mac=mac,
        nonce=nonce,
        pk=pk,
        sk=sk,
    )
    assert msg == b'foo'


def test_crypto_secretbox_invalid_nonce(k):
    with pytest.raises(AssertionError):
        crypto_secretbox(
            msg=b'foo',
            nonce=b'',
            k=k,
        )


def test_crypto_secretbox_invalid_k(nonce):
    with pytest.raises(AssertionError):
        crypto_secretbox(
            msg=b'foo',
            nonce=nonce,
            k=b'',
        )


def test_crypto_secretbox(nonce, k):
    c = crypto_secretbox(
        msg=b'foo',
        nonce=nonce,
        k=k,
    )
    assert isinstance(c, binary_type)


def test_crypto_secretbox_open_invalid_nonce(k):
    with pytest.raises(AssertionError):
        crypto_secretbox_open(
            c=b'',
            nonce=b'',
            k=k,
        )


def test_crypto_secretbox_open_invalid_k(nonce):
    with pytest.raises(AssertionError):
        crypto_secretbox_open(
            c=b'',
            nonce=nonce,
            k=b'',
        )


def test_crypto_secretbox_open(nonce, k):
    c = crypto_secretbox(
        msg=b'foo',
        nonce=nonce,
        k=k,
    )
    msg = crypto_secretbox_open(
        c=c,
        nonce=nonce,
        k=k,
    )
    assert msg == b'foo'


def test_crypto_generichash_blake2b_salt_key_too_short(salt):
    with pytest.raises(AssertionError):
        crypto_generichash_blake2b_salt_personal(
            in_=None,
            key=b'1',
            salt=salt,
            personal=None,
        )


def test_crypto_generichash_blake2b_salt_salt_too_short(key):
    with pytest.raises(AssertionError):
        crypto_generichash_blake2b_salt_personal(
            in_=None,
            key=key,
            salt=b'x',
            personal=None,
        )


def test_crypto_generichash_blake2b_salt_personal_too_short(key, salt):
    with pytest.raises(AssertionError):
        crypto_generichash_blake2b_salt_personal(
            in_=None,
            key=key,
            salt=salt,
            personal=b'x',
        )


def test_crypto_generichash_blake2b_salt_invalid_outlen(key, salt, personal):
    with pytest.raises(AssertionError):
        crypto_generichash_blake2b_salt_personal(
            in_=None,
            key=key,
            salt=salt,
            personal=personal,
            outlen=1,
        )


def test_crypto_generichash_blake2b_salt_personal(key, salt, personal):
    out = crypto_generichash_blake2b_salt_personal(
        in_=None,
        key=key,
        salt=salt,
        personal=personal,
    )
    assert isinstance(out, binary_type)


def test_crypto_generichash_blake2b_salt(key, salt):
    out = crypto_generichash_blake2b_salt_personal(
        in_=None,
        key=key,
        salt=salt,
        personal=None,
        outlen=35,
    )
    assert isinstance(out, binary_type)
    assert len(out) == 35
