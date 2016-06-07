#!/bin/bash
cd source
echo "clean"

rm -rf fileSystem
rm -rf hashtab
rm -rf libsecurity
rm -rf src

echo "build"
base=../../../..
rsync --checksum --archive --delete --exclude=expli* --exclude=__expli* --exclude=stubs.c --exclude=testing/ --exclude=utils/app/ --exclude=examples/ --exclude=*.o $base/libsecurity/src/ src/
rsync --checksum --archive --delete --exclude=acl* --exclude=full* --exclude=otp* --exclude=secure* $base/libsecurity/src/examples/ src/examples/
rsync --checksum --archive --delete $base/libsecurity/include/libsecurity/ libsecurity/
rsync --checksum --archive --delete $base/deps/hashtab/ --exclude=example/* hashtab/
rsync --checksum --archive --delete $base/deps/fileSystem/ fileSystem/
cd ..
