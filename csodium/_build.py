"""
C implementation.
"""

import cffi
import sys


ffi = cffi.FFI()

# Here we list the functions we use and import.
ffi.cdef('''
int sodium_init();
const char* sodium_version_string();

void randombytes(unsigned char* const buf, const unsigned long long buf_len);

size_t crypto_box_beforenmbytes(void);
size_t crypto_box_macbytes(void);
size_t crypto_box_noncebytes(void);
size_t crypto_box_publickeybytes(void);
size_t crypto_box_sealbytes(void);
size_t crypto_box_secretkeybytes(void);
size_t crypto_box_seedbytes(void);

int crypto_box_keypair(unsigned char*, unsigned char*);
int crypto_box_seed_keypair(
    unsigned char*,
    unsigned char*,
    const unsigned char*
);
int crypto_box_beforenm(
    unsigned char* k,
    const unsigned char* pk,
    const unsigned char* sk
);
int crypto_box_easy(
    unsigned char* c,
    const unsigned char* m,
    unsigned long long mlen,
    const unsigned char* n,
    const unsigned char* pk,
    const unsigned char *sk
);
int crypto_box_easy_afternm(
    unsigned char* c,
    const unsigned char* m,
    unsigned long long mlen,
    const unsigned char* n,
    const unsigned char *k
);
int crypto_box_open_easy(
    unsigned char* m,
    const unsigned char* c,
    unsigned long long clen,
    const unsigned char* n,
    const unsigned char* pk,
    const unsigned char* sk
);
int crypto_box_open_easy_afternm(
    unsigned char* m,
    const unsigned char* c,
    unsigned long long clen,
    const unsigned char* n,
    const unsigned char* k
);
int crypto_box_seal(
    unsigned char* c,
    const unsigned char* m,
    unsigned long long mlen,
    const unsigned char* pk
);
int crypto_box_seal_open(
    unsigned char* m,
    const unsigned char* c,
    unsigned long long clen,
    const unsigned char* pk,
    const unsigned char* sk
);
int crypto_box_detached(
    unsigned char* c,
    unsigned char* mac,
    const unsigned char* m,
    unsigned long long mlen,
    const unsigned char* n,
    const unsigned char* pk,
    const unsigned char* sk
);
int crypto_box_open_detached(
    unsigned char* m,
    const unsigned char* c,
    const unsigned char* mac,
    unsigned long long clen,
    const unsigned char* n,
    const unsigned char* pk,
    const unsigned char* sk
);

size_t crypto_secretbox_keybytes(void);
size_t crypto_secretbox_noncebytes(void);
size_t crypto_secretbox_macbytes(void);
int crypto_secretbox_easy(
    unsigned char* c,
    const unsigned char* m,
    unsigned long long mlen,
    const unsigned char* n,
    const unsigned char* k
);
int crypto_secretbox_open_easy(
    unsigned char* m,
    const unsigned char* c,
    unsigned long long clen,
    const unsigned char* n,
    const unsigned char* k
);

size_t crypto_generichash_blake2b_bytes_min(void);
size_t crypto_generichash_blake2b_bytes_max(void);
size_t crypto_generichash_blake2b_bytes(void);
size_t crypto_generichash_blake2b_keybytes_min(void);
size_t crypto_generichash_blake2b_keybytes_max(void);
size_t crypto_generichash_blake2b_keybytes(void);
size_t crypto_generichash_blake2b_saltbytes(void);
size_t crypto_generichash_blake2b_personalbytes(void);

int crypto_generichash_blake2b_salt_personal(
    uint8_t* out,
    const uint8_t outlen,
    const void* in,
    const uint64_t inlen,
    const void* key,
    uint8_t keylen,
    const void* salt,
    const void* personal
);

size_t  crypto_sign_bytes(void);
size_t  crypto_sign_seedbytes(void);
size_t  crypto_sign_publickeybytes(void);
size_t  crypto_sign_secretkeybytes(void);

int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen_p,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);
int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *sk);
int crypto_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk);



size_t crypto_sign_ed25519_seedbytes(void);
size_t crypto_sign_ed25519_publickeybytes(void);
size_t crypto_sign_ed25519_secretkeybytes(void);
size_t crypto_scalarmult_curve25519_bytes(void);

int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                         const unsigned char *ed25519_pk);
int crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                         const unsigned char *ed25519_sk);
int crypto_sign_ed25519_sk_to_seed(unsigned char *seed,
                                   const unsigned char *sk);
int crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);


''')

# On Windows, we compile with libsodium statically, so that users of the wheel
# don't have to set their PATH and install libsodium on their system.
if sys.platform == 'win32':
    libraries = ['libsodium']
    define_macros = [
        ('SODIUM_STATIC', '1'),
        ('SODIUM_EXPORT',),
    ]
    extra_compile_args = []
else:
    libraries = ['sodium']
    define_macros = []
    extra_compile_args = [
        '-Wno-unreachable-code',
    ]

# This creates a binary module `csodium._impl` that contains the imported
# functions.
ffi.set_source(
    'csodium._impl',
    '#include <sodium.h>',
    libraries=libraries,
    define_macros=define_macros,
    extra_compile_args=extra_compile_args,
)

if __name__ == '__main__':
    ffi.compile()
    # TODO: Investigate possible usage of ffi.dlopen() as an alternative to
    # compilation.
