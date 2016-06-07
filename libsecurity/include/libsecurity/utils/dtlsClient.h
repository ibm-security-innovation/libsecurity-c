#pragma once

#include <stdint.h>
#include <string.h>

#include "libsecurity/utils/utils.h"

#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"

#define SERVER_PORT_LEN 10

#ifdef MBED_OS

#include "mbed-drivers/mbed.h"
#include "EthernetInterface.h"
#include "sockets/UDPSocket.h"
#include "sal-stack-lwip/lwipv4_init.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

bool DTLS_ClientInit(const char *cacertFile, const char *serverAddr, int16_t port, const char *serverName);
bool DTLS_ClientSendPacket(const uint8_t *body, int body_len);
void DTLS_ClientFree(void);
bool DTLS_GetRandom(unsigned char *random, int16_t len);

#ifdef __cplusplus
}
#endif
