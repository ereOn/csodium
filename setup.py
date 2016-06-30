from setuptools import (
    setup,
    find_packages,
)

setup(
    name='csodium',
    author='Julien Kauffmann',
    author_email='julien.kauffmann@freelan.org',
    maintainer='Julien Kauffmann',
    maintainer_email='julien.kauffmann@freelan.org',
    version=open('VERSION').read().strip(),
    url='http://ereOn.github.io/csodium',
    description=(
        "A standalone Python interface for libsodium."
    ),
    long_description="""\
csodium is a pysodium-compatible Python package that provides libsodium
bindings. It does not require any libsodium installation on the target system.
""",
    packages=find_packages(exclude=[
        'tests',
    ]),
    setup_requires=[
        'cffi>=1.7.0,<2',
    ],
    install_requires=[
        'cffi>=1.7.0,<2',
        'six>=1.10.0,<2',
    ],
    cffi_modules=["csodium/_build.py:ffi"],
    test_suite='tests',
    classifiers=[
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Development Status :: 5 - Production/Stable',
    ],
    zip_safe=False,
)
