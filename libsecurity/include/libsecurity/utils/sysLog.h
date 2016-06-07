#pragma once

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>

#include "libsecurity/utils/utils.h"
#include "libsecurity/utils/networkAdapters.h"
#include "libsecurity/libsecurity/libsecurity_params.h"

#define SYSLOG_VERSION 1

// From SYSLOG RFC 5234
enum SyslogSevirity {
  SevirityEmerggency = 0,
  SevirityAlert,
  SevirityCritical,
  SevirityError,
  SevirityWarning,
  SevirityNotice,
  SevirityInformation,
  SevirityDebug
};

enum MuleCommands { MuleAdd = 1, MuleSet, MuleMax };

#define SYSLOG_MAX_LOG_LINE_LEN 1024

#define SYSLOG_USE_MAC_ADDRESS_AS_HOST_IDX 0
#define SYSLOG_USE_IP_ADDRESS_AS_HOST_IDX 1

bool Syslog_SetDtls(bool setDtls);
bool Syslog_OpenLog(const char *serverIpStr, int16_t port, const char *cacertFile, const char *serverName);
bool Syslog_Log(int16_t severity, const char *format, ...);
bool Syslog_Mule(int16_t type, const char *metric, int16_t val);
void Syslog_CloseLog(void);
bool Syslog_UpdateAppName(const char *str);
bool Syslog_UpdateHostNameType(int16_t type);

void SyslogTest_GetHostName(char *str, int16_t strLen);
