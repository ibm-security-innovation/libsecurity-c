#!/bin/bash

cmd=( "clang" "gcc-c" "gcc-o")
cmd=( "gcc-c")

path=("storage/test" "entity/test" "acl/test" "otp/test" "salt/test" "password/test" "accounts/test" "utils/test"
      "examples/otpExample" "examples/aclExample" "examples/fullExample" "examples/secureStorageExample" "examples/appExample")

#path=("storage/test")

c1=`pwd`
cpwd=$c1/res
mkdir res >& /dev/null
rm -f $cpwd/res
rm -f $cpwd/res-cov
rm -f $cpwd/full-res

if [ "$1" = "COV" ] || [ "$2" = "COV" ]; then
   export COV="1"
fi      

for c in "${cmd[@]}"
do
   echo "running " $c >> $cpwd/res
   rm -f $cpwd/tmp-res
   if [ $c == "gcc-c" ]
   then
      echo "****** compile using gcc ******"
      export COMPILER="GCC_C"
   elif [ $c == "gcc-o" ]
   then
      echo "****** compile using gcc with optimization ******"
      export COMPILER="GCC_O"
   else
      echo "****** compile using clang ******"
      export COMPILER="CLANG"
   fi
   for p in "${path[@]}"
   do
      echo "Test " $p
      echo "check " $p >> $cpwd/tmp-res
      pushd . >& /dev/null
      cd ../$p
      ./run.sh &>> $cpwd/tmp-res
      cd ..
      if [ -n "$COV" ]; then
         gcovr -r . | tee $cpwd/tmp
         cat $cpwd/tmp >> $cpwd/res-cov
      fi      
      popd >& /dev/null
   done
   grep -i "in use at exit" < $cpwd/tmp-res >> $cpwd/res
   grep -i "ERROR SUMMARY:" < $cpwd/tmp-res >> $cpwd/res
   grep -i "ERROR:" < $cpwd/tmp-res >> $cpwd/res
   grep -i "make.* Error" < $cpwd/tmp-res >> $cpwd/res
   grep -iwE 'pass|check' < $cpwd/tmp-res >> $cpwd/res
   grep -i fail < $cpwd/tmp-res >> $cpwd/res
   grep -i fail < $cpwd/tmp-res
   grep  "error:" < $cpwd/tmp-res
   cat $cpwd/tmp-res >> $cpwd/full-res
done

if [ "$1" = "CHECK" ] || [ "$2" = "CHECK" ]; then
   if [ -z "$COV" ]; then
      echo "Formatting code"
      ./formatCode.sh
      echo "Verify code"
      ./cleanCode.sh
   fi
fi

unset COV
export COMPILER="GCC_C"

echo "full results are in: " $cpwd/full-res
echo "summary results are in: " $cpwd/res
