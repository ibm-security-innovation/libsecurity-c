# iotClient

**ioClient** is a demo application that sends MULE or log messages to server.
The messages can be sent in one of two forms:
1. Clear text to Linux rsyslog
2. Encrypted using DTLS (over UDP) to goldy server (in this case you will need to download and run goldy application as well as open the relevant ports on the iptables)

## Build

To build iotClient from source:

    gitlab clone .../libsecurity-c
    cd libsecurity-c/libsecurity/src/examples/appExample
    ./run.sh
    ./iotClient [override on the default parameters if needed]

## Help

    Usage: iotClient
    Options:
    -h      server_host_ip                              (default 127.0.0.1)
    -p      server_port                                 (default 8514)
    -i      interval_in_sec                             (default 1 sec)
    -b      base_val                                    (default 1)
    -f      high_val                                    (default 100)
    -m      min_random_val                              (default 10)
    -x      max_random_val                              (default 20)
    -s      intervals_of_base_values                    (default 3)
    -e      intervals_of_high_values                    (default 1)
    -l      number_of_intervals_between_log_messages    (default 4)
    -H      this help

Note: All flags are optional
