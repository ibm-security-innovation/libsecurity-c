#!/bin/bash

code=(
   "utils" "entity" "salt" "password" "accounts" "otp" "acl" "storage"
)

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

echo
echo
echo "*****************"
echo "You may need to restart the rsyslog server: sudo service rsyslog restart"
echo "*****************"

EXE=./test_utils
if [ "$COMPILER" == "CLANG" ]; then
	ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.4 $EXE
else
	if [ -n "$PURE" ]; then
		 $EXE
	else
		valgrind --track-origins=yes --tool=memcheck --leak-check=full $EXE
	fi
fi

if [ -n "$CLEAN_TEST" ]; then
	rm -f ./test_utils
fi

make clean
