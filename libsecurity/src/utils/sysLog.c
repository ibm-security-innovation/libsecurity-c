/* Our Syslog Message Format (subset of RFC5424):
SYSLOG-MSG              = HEADER SP STRUCTURED-DATA [SP MSG]
Our log SYSLOG-MSG      = HEADER SP - SP MSG
Our matrics SYSLOG-MSG  = HEADER SP STRUCTURED-DATA

Original HEADER       = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP
PROCID SP MSGID
Our HEADER            = PRI VERSION SP - SP HOSTNAME SP APP-NAME SP - SP
OUR-MSGID

      PRI             = "<" PRIVAL ">"
      PRIVAL          = 1*3DIGIT ; range 0 .. 191
      Our implementation:
            PRIVAL          = 1*2DIGIT ; range 8 .. 15

            Facility is always : 1             user-level messages

            Numerical         Severity
             Code
              0       Emergency: system is unusable
              1       Alert: action must be taken immediately
              2       Critical: critical conditions
              3       Error: error conditions
              4       Warning: warning conditions
              5       Notice: normal but significant condition
              6       Informational: informational messages
              7       Debug: debug-level messages

      VERSION         = NONZERO-DIGIT 0*2DIGIT

      MSGID           = NILVALUE / 1*32PRINTUSASCII
      OUR-MSGID       = M for metrics or L for log

      APP-NAME        = NILVALUE / 1*32VALID-TEXT

      STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
      SD-ELEMENT      = "[" SD-ID SP SD-PARAM "]"
      SD-PARAM        = PARAM-NAME "=" %d34 PARAM-VALUE %d34
      SD-ID           = SD-NAME, Our implementation: M@1 or M@2 or M@3
            M@1 (MULE_ADD): The value is added to the count of the metric for
this particular bucket
            M@2 (MULE_SET): Gauge - The value replaces the number rather than
adding to it
            M#3 (MULE_MAX): High water mark - The maximal value is used

      PARAM-NAME      = SD-NAME (Our implementation: mule matrics without '=',
SP, ']', '"')
      PARAM-VALUE     = UTF-8-STRING: (Our implementation: the value for mule)

      MSG             = MSG-ANY
      MSG-ANY         = *our-OCTET ; not starting with BOM

      our-OCTET       = %d32-255
      SP              = %d32
      PRINTUSASCII    = %d33-126
      NONZERO-DIGIT   = %d49-57
      DIGIT           = %d48 / NONZERO-DIGIT
      VALID-TEXT      = %d65-90 / %d97-122 / DIGIT (A-Z,a-z,0-9)
      NILVALUE        = "-"

Our recommendation for the HOSTNAME option is the device MAC Address,
  additional option - the Device IP address (IPv4 or IPv6),
    if both IP protocols are defined use the one that is returned first,
    usually the IPv4

The format used in our library:
For LOG:
      PRI VERSION SP - SP HOSTNAME SP APP-NAME SP - SP L SP - SP MSG
For Matrics:
      PRI VERSION SP - SP HOSTNAME SP APP-NAME SP - SP M SP [M a.b.c=val]

Examples:
1. <11>1 - 1.2.3.4 Bulb - L - Error while init
   parsing:
   - 10: user level message with error condition
   - 1: Version 1
   - 1.2.3.4: the device ip
   - Bulb: The application name
   - L: its a LOG message
   - Error while init: The log message

2. <14>1 - 1.2.3.4 LightSensor1 - M [M@1 beer.stout.irish="10"]
   parsing:
   - 14: user level message, informational messages
   - 1: Version 1
   - 1.2.3.4: the device ip
   - LightSensor1: The application name
   - M: its a mule metrics
   - [M@1 beer.stout.irish=10]: Mule, Add 10 to the orders of beer.stout.irish

2. <14>1 - 1.2.3.4 - - M [M@2 beer.stout.irish="8"]
   parsing:
   - 14: user level message, informational messages
   - 1: Version 1
   - 1.2.3.4: the device ip
   - No application name
   - M: its a mule metrics
   - [M@2 beer.stout.irish=8]: Mule, Set the value of beer.stout.irish to 8

Notes:
1. The time stamp is added by the server
2. The version is a pre defined number
3. Application name must be set (the default is the NIL string '-'), it may only
contain a-zA-Z0-9
4. The host name is set by the syslog initialization function (and can be
updated by calling to
Syslog_UpdateHostNameType,
  it may either be the MAC or the IP (IPv4 or IPv6) addresses
5. Severity/log messages will be verified by the library
6. Input validity must be verified by the server
7. The protocol is DTLS (Dubek implementation)
8. The flags for openlog: LOG_PERROR, LOG_CONS, LOG_PID and LOG_NDELAY are not
relevant for our log
9. The priority is always LOG_USER
10. Openlog is called as part of the Libsecurity initialization
11. Closelog is call on exit (or never)
12. It is not thread safe (Libsecurity-c is for single thread ARM Cortex-M)
13. The Mulelog Severity is always LOG_INFO
14. For testing purposes, a socket connection may be used
*/
#include "libsecurity/utils/sysLog_int.h"

static bool isLogOpen = false, appNameWasSet = false, isDtls = false;
static int16_t serverId = -1, hostNameType = SYSLOG_USE_MAC_ADDRESS_AS_HOST_IDX;
static char hostName[MAX_HOST_NAME], appName[MAX_APP_NAME];

STATIC bool setMacAddressToHostName() {
  bool ret = false;
  unsigned char mac[MAC_ADDRESS_LEN];
  char macAddress[MAC_ADDRESS_STR_LEN + 1];

  ret = NetworkAdapters_GetMacAddress(mac);
  if (ret == false) return false;
  snprintf(macAddress, sizeof(macAddress), "%02x-%02x-%02x-%02x-%02x-%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  strncpy(hostName, macAddress, MAX_HOST_NAME);
  return true;
}

STATIC bool setHostName(int16_t type) {
  if (type == SYSLOG_USE_MAC_ADDRESS_AS_HOST_IDX)
    return setMacAddressToHostName();
  else
    return NetworkAdapters_SetIpToHostName(hostName);
}

bool Syslog_SetDtls(bool setDtls) {
  isDtls = setDtls;
  return isDtls;
}

// Update the application name only if the given string is valid (a-z,A-Z,0-9)
bool Syslog_UpdateAppName(const char *str) {
  int16_t i = 0, len = strlen(str);

  if (appNameWasSet == false) snprintf(appName, sizeof(appName), NOT_VALID_APP_NAME);
  if (len == 0) return false;
  for (i = 0; i < len; i++) {
    if (!isalpha((unsigned char)str[i]) && !isdigit((unsigned char)str[i])) {
      snprintf(errStr, sizeof(errStr), "Error: new App name '%s' is illegal, char '%c' at %d\n", str, str[i], i);
      return false;
    }
  }
  strncpy(appName, str, MAX_APP_NAME);
  return true;
}

bool Syslog_UpdateHostNameType(int16_t type) {
  if (type < SYSLOG_USE_MAC_ADDRESS_AS_HOST_IDX || type > SYSLOG_USE_IP_ADDRESS_AS_HOST_IDX) {
    snprintf(errStr, sizeof(errStr), "Error: new host name type %d is not in the range %d-%d\n", type, SYSLOG_USE_MAC_ADDRESS_AS_HOST_IDX,
             SYSLOG_USE_IP_ADDRESS_AS_HOST_IDX);
    return false;
  }
  hostNameType = type;
  setHostName(hostNameType);
  return false;
}

bool Syslog_OpenLog(const char *serverIpStr, int16_t port, const char *cacertFile, const char *serverName) {
  strncpy(hostName, SYSLOG_NIL_STR, strlen(SYSLOG_NIL_STR));

  setHostName(hostNameType);
  if (isDtls)
    isLogOpen = NetworkAdapters_OpenDTLSClient(serverIpStr, port, &serverId, cacertFile, serverName);
  else
    isLogOpen = NetworkAdapters_OpenClient(serverIpStr, port, &serverId, cacertFile, serverName);
  return isLogOpen;
}

bool Syslog_Log(int16_t severity, const char *format, ...) {
  char str[SYSLOG_MAX_LOG_LINE_LEN];
  va_list arglist;

  va_start(arglist, format);
  vsnprintf(str, sizeof(str), format, arglist);
  va_end(arglist);

  if (isLogOpen == false) {
    snprintf(errStr, sizeof(errStr), "Syslog must be open before sending data to Syslog_Log");
    return false;
  }
  if (severity < SevirityEmerggency || severity > SevirityDebug) return false;
  snprintf(errStr, sizeof(errStr), "<%d>%d %s %s %s %s %s %s %s", USER_LEVEL_MESSAGES * FACILITY_MULTIPLYING + severity, SYSLOG_VERSION,
           SYSLOG_NIL_STR, hostName, appName, SYSLOG_NIL_STR, SYSLOG_LOG_STR, SYSLOG_NIL_STR, str);
  if (isDtls)
    return NetworkAdapters_SendDTLSData(serverId, errStr, strlen(errStr));
  else
    return NetworkAdapters_SendData(serverId, errStr, strlen(errStr));
}

bool Syslog_Mule(int16_t type, const char *metric, int16_t val) {
  if (isLogOpen == false) {
    snprintf(errStr, sizeof(errStr), "Syslog must be open before sending data to Syslog_Mule");
    return false;
  }
  if (type < MuleAdd || type > MuleMax) return false;
  snprintf(errStr, sizeof(errStr), "<%d>%d %s %s %s %s %s [%s@%d %s=\"%d\"]", USER_LEVEL_MESSAGES * FACILITY_MULTIPLYING + SevirityInformation,
           SYSLOG_VERSION, SYSLOG_NIL_STR, hostName, appName, SYSLOG_NIL_STR, SYSLOG_MULE_STR, SYSLOG_MULE_STR, type, metric, val);
  if (isDtls)
    return NetworkAdapters_SendDTLSData(serverId, errStr, strlen(errStr));
  else
    return NetworkAdapters_SendData(serverId, errStr, strlen(errStr));
}

void Syslog_CloseLog(void) {
  isLogOpen = false;

  if (isDtls)
    NetworkAdapters_CloseDTLSLog(serverId);
  else
    NetworkAdapters_CloseLog(serverId);
}

void SyslogTest_GetHostName(char *str, int16_t strLen) {
  snprintf(str, strLen, "%s", hostName);
}
