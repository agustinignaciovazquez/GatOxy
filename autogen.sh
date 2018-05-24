#!/bin/sh

autoreconf --install --force || exit 1

echo "Now run ./configure, make, and make install."
