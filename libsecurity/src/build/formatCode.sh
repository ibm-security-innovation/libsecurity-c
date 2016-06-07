#!/bin/bash

path=("utils" "storage" "entity" "acl" "otp" "salt" "password" "accounts")
#path=("storage")
for c in "${path[@]}"
do
   echo "Formatting " $c
   clang-format-3.6 -i ../$c/*.[c*]
   clang-format-3.6 -i ../$c/test/test_*.[ch]
   clang-format-3.6 -i ../../include/libsecurity/$c/*.h
done
