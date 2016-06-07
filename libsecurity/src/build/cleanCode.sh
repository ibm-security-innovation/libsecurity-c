#!/bin/bash

code=(
   "utils" "entity" "salt" "password" "accounts" "storage" "acl" "otp" "examples/fullExample" "examples/secureStorageExample" "examples/aclExample" "examples/otpExample"
)

#code=( "entity")

for c in "${code[@]}" 
do
	pushd . >& /dev/null
	cd ../$c
	echo "check " $c
	scan-build make | grep -i "scan-build" | grep -i "bugs found" | grep -iv "No bugs found."
	popd >& /dev/null
done

if [ -z "$COV" ]; then

testCode=(
   "utils/test" "entity/test" "salt/test" "password/test" "accounts/test" "storage/test" "acl/test" "otp/test"
)

for c in "${testCode[@]}" 
do
	pushd . >& /dev/null
	cd ../$c
	echo "check " $c
	scan-build make STATIC_F=-DSTATIC_F | grep -i "scan-build" | grep -i "bugs found" | grep -iv "No bugs found."
	popd >& /dev/null
done

fi

