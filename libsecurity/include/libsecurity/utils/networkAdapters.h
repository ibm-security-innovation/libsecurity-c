#pragma once

#define MAX_HOST_NAME 32
#define MAX_APP_NAME 32

#define MAC_ADDRESS_LEN 6
#define MAC_ADDRESS_STR_LEN (3 * MAC_ADDRESS_LEN)

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

bool NetworkAdapters_SetIpToHostName(char hostName[MAX_HOST_NAME]);
bool NetworkAdapters_GetMacAddress(unsigned char mac[MAC_ADDRESS_LEN]);

bool NetworkAdapters_OpenClient(const char *serverIpStr, int16_t port, int16_t *serverId, const char *cacertFile, const char *serverName);
bool NetworkAdapters_SendData(int16_t serverId, const char *str, int16_t sLen);
bool NetworkAdapters_CloseLog(int16_t serverId);

bool NetworkAdapters_OpenDTLSClient(const char *serverIpStr, int16_t port, int16_t *serverId, const char *cacertFile, const char *serverName);
bool NetworkAdapters_SendDTLSData(int16_t serverId, const char *str, int16_t sLen);
bool NetworkAdapters_CloseDTLSLog(int16_t serverId);

#ifdef MBED_OS

bool NetworkAdapters_GetEth(void **eth1);
#endif

#ifdef __cplusplus
}
#endif
