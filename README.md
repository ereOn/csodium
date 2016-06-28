[![Build Status](https://travis-ci.org/ereOn/csodium.svg?branch=master)](https://travis-ci.org/ereOn/csodium)
[![Coverage Status](https://coveralls.io/repos/ereOn/csodium/badge.svg?branch=master&service=github)](https://coveralls.io/github/ereOn/csodium?branch=master)
[![Documentation Status](https://readthedocs.org/projects/csodium/badge/?version=latest)](http://csodium.readthedocs.org/en/latest/?badge=latest)
[![PyPI](https://img.shields.io/pypi/pyversions/csodium.svg)](https://pypi.python.org/pypi/csodium/1.0.0)
[![PyPi version](https://img.shields.io/pypi/v/csodium.svg)](https://pypi.python.org/pypi/csodium/1.0.0)
[![PyPi downloads](https://img.shields.io/pypi/dm/csodium.svg)](https://pypi.python.org/pypi/csodium/1.0.0)

# csodium

**csodium** is a Python 2/3 standalone interface for `libsodium`.

## Rationale

`csodium` was started as the result of a
[disagreement](https://github.com/stef/pysodium/issues/45) with `pysodium`
maintainers. They wanted the library to remain a simple wrapper (using `ctypes`
to dynamically load `libsodium` at runtime, mainly to always use the latest
system available `libsodium`) while we wanted it to be a standalone package
that would work out of the box, especially for Windows/Mac OSX wheel users.
The goal being they would not need to install/compile `libsodium` and could
just do `pip install` to get things started.

As an attempt to make the best out of those two opinions, `csodium` was
initiated, which aims at providing an out-of-the-box, ready-to-use `libsodium`
Python interface while still giving the ability to Linux and OSX users to
recompile and/or use the latest available `libsodium` if they want to.

`csodium` aims to be compatible with `pysodium`, but there is **no syncing** of
any kind between the two projects as of now, so their APIs might diverge in the
future.

## Installation

You may install it by using `pip`:

> pip install csodium
