#!/bin/bash

code=(
   "utils" "entity" "storage" "salt" "password" "acl"
)

#code=("entity")

if [ "$1" = "COV" ] || [ "$2" = "COV" ]; then
   export COV="1"
fi

c1=`pwd`
for c in "${code[@]}"
do
	pushd . >& /dev/null
	cd ../../$c
	make clean
	make STATIC_F=-DSTATIC_F
	popd >& /dev/null
done

cd $c1
make clean
make STATIC_F=-DSTATIC_F

EXE=./test_password
if [ "$COMPILER" == "CLANG" ]; then
	ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.4 $EXE
else
	if [ -n "$PURE" ]; then
		 $EXE
	else
		valgrind --tool=memcheck --leak-check=full $EXE
	fi
fi

if [ -n "$COV" ]; then
	pushd . >& /dev/null
	cd ..
    gcovr -r . --gcov-filter="password*" --html --html-details -o cov.html
	popd >& /dev/null
fi
unset COV

if [ -n "$CLEAN_TEST" ]; then
	rm -f ./test_password
fi

make clean
