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
