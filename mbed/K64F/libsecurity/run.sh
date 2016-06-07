./build.sh
rm -f mnt/libsecurity.bin
ls mnt
#sudo umount mnt
yotta build
#./mount.sh $1
#sleep 2
cp build/frdm-k64f-gcc/source/libsecurity.bin mnt/
sleep 6
ls mnt
echo "reset K64F"
