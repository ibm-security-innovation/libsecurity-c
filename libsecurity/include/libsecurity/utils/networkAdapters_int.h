#pragma once

#include "libsecurity/utils/networkAdapters.h"

#define LOCAL_HOST_IP "127.0.0.1"

#ifdef LINUX_OS
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
// for the inet_aon
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <unistd.h>

#elif MBED_OS
#include "sockets/UDPSocket.h"

#include <string.h>

#else
#endif
