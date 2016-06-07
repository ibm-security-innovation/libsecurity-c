#!/bin/bash

idx=$1
echo "idx = " $1
mkdir $1-ram-disk
sudo chmod 777 $1-ram-disk
sudo mount -t tmpfs -o size=2000M tmpfs $1-ram-disk
cd $1-ram-disk
cp ../libsecurity .
mkdir testcases
cp ../input/*/* testcases
rm -f testcases/all
mkdir findings
echo "AFL_SKIP_CPUFREQ=1 afl-fuzz -i testcases -o findings ./libsecurity @@ fastuser fastotp fastotpuser fastacl fastam fastpwd" > run.sh
chmod 777 ./run.sh
