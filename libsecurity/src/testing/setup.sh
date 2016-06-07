pushd .
sudo sh -c 'echo core >/proc/sys/kernel/core_pattern'
cd /sys/devices/system/cpu
sudo sh -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
popd
