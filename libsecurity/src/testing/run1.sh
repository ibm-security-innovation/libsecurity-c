#!/bin/bash

#export COMPILER="GCC_C"
#unset AFL

export COMPILER="GCC_C"
export AFL="1"

code=(
   "utils" "entity" "otp" "salt" "acl" "password" "accounts" "storage"
)

#code=("entity")

c1=`pwd`
for c in "${code[@]}" 
do
	pushd . >& /dev/null
	cd ../$c
	make clean
	make
	popd >& /dev/null
done

cd $c1
make clean
make

if [ "$COMPILER" == "CLANG" ]; then
	ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.4 ./libsecurity;
else
	valgrind --tool=memcheck --leak-check=full libsecurity;
fi

unset AFL

make clean
