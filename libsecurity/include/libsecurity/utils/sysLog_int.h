#pragma once

#include <sys/types.h>

#include "libsecurity/utils/sysLog.h"
#include "libsecurity/utils/networkAdapters.h"

#define USER_LEVEL_MESSAGES 1
#define FACILITY_MULTIPLYING 8 // from RFC 5234

#define SYSLOG_NIL_STR "-"

#define SYSLOG_LOG_STR "L"
#define SYSLOG_MULE_STR "M"

#define NOT_VALID_APP_NAME "NotValidApp"

STATIC bool setHostName(int16_t type);
STATIC bool setMacAddressToHostName(void);
