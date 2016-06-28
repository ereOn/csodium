"""
C implementation.
"""

import cffi
import sys


ffi = cffi.FFI()

# Here we list the functions we use and import.
ffi.cdef('''
int sodium_init();

void randombytes(unsigned char* const buf, const unsigned long long buf_len);
''')

# On Windows, we compile with libsodium statically, so that users of the wheel
# don't have to set their PATH and install libsodium on their system.
if sys.platform == 'win32':
    libraries = ['libsodium']
    define_macros = [
        ('SODIUM_STATIC', '1'),
        ('SODIUM_EXPORT',),
    ]
else:
    libraries = ['sodium']
    define_macros = []

# This creates a binary module `csodium._impl` that contains the imported
# functions.
ffi.set_source(
    'csodium._impl',
    '#include <sodium.h>',
    libraries=libraries,
    define_macros=define_macros,
)

if __name__ == '__main__':
    ffi.compile()
