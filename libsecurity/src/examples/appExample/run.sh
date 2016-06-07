#!/bin/bash

code=(
   "utils"
)

c1=`pwd`
for c in "${code[@]}"
do
	pushd . >& /dev/null
	cd ../../$c
	make clean
	make 
	popd >& /dev/null
done

cd $c1
make clean
make 

echo
echo
echo "*****************"
echo "You may need to restart the rsyslog server: sudo service rsyslog restart"
echo "*****************"

make clean
#./iotClient
