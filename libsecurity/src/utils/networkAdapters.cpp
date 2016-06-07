#include "libsecurity/utils/networkAdapters_int.h"
#include "libsecurity/utils/UDPSyslog.h"
#include "libsecurity/utils/dtlsClient.h"

#ifdef MBED_OS
UDPSyslog *UDPSyslog::_pInstance = NULL;
#endif

extern "C" {

#include "libsecurity/utils/utils.h"
#include "libsecurity/utils/dtlsClient.h"

static bool connectionIsOpen = false;
static bool connectionIsDtls = false;

#if defined(LINUX_OS)

// First come first serve (in case there is more than a single IPv4 or IPv6 addresses on eth that
// are not local hosts)
bool NetworkAdapters_SetIpToHostName(char hostName[MAX_HOST_NAME]) {
  struct ifaddrs *ifaddr, *ifa;
  int16_t family, s, n, found = false, len = 0;
  char host[MAX_HOST_NAME];
  char *ptr = NULL;

  if (getifaddrs(&ifaddr) == -1) return false;
  for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
    if (ifa->ifa_addr == NULL) continue;
    family = ifa->ifa_addr->sa_family;
    if (family == AF_INET || family == AF_INET6) {
      s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, MAX_HOST_NAME,
                      NULL, 0, NI_NUMERICHOST);
      if (s != 0) {
        return false;
      }
      if (family == AF_INET && strcmp(host, LOCAL_HOST_IP) != 0) {
        strncpy(hostName, host, MAX_HOST_NAME);
        found = true;
        break;
      }
      ptr = strstr(host, "eth");
      if (family == AF_INET6 && ptr != NULL) {
        len = MAX_HOST_NAME;
        if ((int16_t)(strlen(host) - strlen(ptr) - 2) < len) len = strlen(host) - strlen(ptr) - 2;
        strncpy(hostName, host, len);
        found = true;
        break;
      }
    }
  }
  freeifaddrs(ifaddr);
  return found;
}

// Get the MAC address: it's a unique id for the IoT
bool NetworkAdapters_GetMacAddress(unsigned char mac[MAC_ADDRESS_LEN]) {
  int16_t i = 0;
  struct ifreq s;
  int16_t fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, "eth0");
  if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
    for (i = 0; i < MAC_ADDRESS_LEN; ++i) {
      mac[i] = (unsigned char)s.ifr_addr.sa_data[i];
    }
    return true;
  }
  return false;
}

#endif

bool NetworkAdapters_OpenDTLSClient(const char *serverIpStr, int16_t port, int16_t *serverId, const char *cacertFile, const char *serverName) {
  (void)serverId;
  if (Utils_IsIpStrValid(serverIpStr) == false) return false;
  if (cacertFile != NULL && serverName != NULL) {
    connectionIsDtls = true;
    bool ret = DTLS_ClientInit(cacertFile, serverIpStr, port, serverName);
    if (ret) connectionIsOpen = true;
    return ret;
  }
  snprintf(errStr, sizeof(errStr), "NetworkAdapters_OpenClient: CA certificate file and server name must not be NULL");
  return false;
}

bool NetworkAdapters_SendDTLSData(int16_t serverId, const char *str, int16_t sLen) {
  (void)serverId;
  if (connectionIsOpen == false) {
    snprintf(errStr, sizeof(errStr), "The connection must be set first");
    return false;
  }
  if (connectionIsDtls) {
    return DTLS_ClientSendPacket((const uint8_t *)str, sLen);
  }
  snprintf(errStr, sizeof(errStr), "NetworkAdapters_SendData: DTLS flag was not set");
  return false;
}

bool NetworkAdapters_CloseDTLSLog(int16_t serverId) {
  (void)serverId;
  if (connectionIsOpen == false) {
    snprintf(errStr, sizeof(errStr), "The connection must be set first");
    return false;
  }
  DTLS_ClientFree();
  connectionIsOpen = false;
  connectionIsDtls = false;
  return true;
}

#if defined(LINUX_OS)

static struct sockaddr_in serverSocket;

bool NetworkAdapters_OpenClient(const char *serverIpStr, int16_t port, int16_t *serverId, const char *cacertFile, const char *serverName) {
  (void)cacertFile;
  (void)serverName;
  if (Utils_IsIpStrValid(serverIpStr) == false) return false;
  if (((*serverId) = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    snprintf(errStr, sizeof(errStr), "Can't open socket");
    return false;
  }
  memset((char *)&serverSocket, 0, sizeof(serverSocket));
  serverSocket.sin_family = AF_INET;
  serverSocket.sin_port = htons(port);
  if (inet_aton(serverIpStr, &serverSocket.sin_addr) == 0) {
    snprintf(errStr, sizeof(errStr), "inet_aton() failed");
    return false;
  }
  connectionIsOpen = true;
  return true;
}

bool NetworkAdapters_SendData(int16_t serverId, const char *str, int16_t sLen) {
  if (connectionIsOpen == false) {
    snprintf(errStr, sizeof(errStr), "The connection must be set first");
    return false;
  }
  if (sendto(serverId, str, sLen, 0, (struct sockaddr *)&serverSocket, sLen) == -1) {
    return false;
  }
  return true;
}

bool NetworkAdapters_CloseLog(int16_t serverId) {
  if (connectionIsOpen == false) {
    snprintf(errStr, sizeof(errStr), "The connection must be set first");
    return false;
  }
  close(serverId);
  connectionIsOpen = false;
  connectionIsDtls = false;
  return true;
}

#elif defined(MBED_OS)

UDPSyslog *udpSysLog;
static EthernetInterface eth;
static bool ethWasSet = false;

bool NetworkAdapters_GetEth(void **eth1) {
  if (ethWasSet == false) {
    eth.init();
    eth.connect();
    ethWasSet = true;
  }
  *eth1 = (void *)(&eth);
  return true;
}

bool NetworkAdapters_SetIpToHostName(char hostName[MAX_HOST_NAME]) {
  EthernetInterface *eth1 = NULL;

  NetworkAdapters_GetEth((void **)&eth1);
  snprintf(hostName, MAX_HOST_NAME, "%15s", eth1->getIPAddress());
  return true;
}

bool NetworkAdapters_GetMacAddress(unsigned char mac[MAC_ADDRESS_LEN]) {
  mbed_mac_address((char *)mac);
  return true;
}

bool NetworkAdapters_OpenClient(const char *serverIpStr, int16_t port, int16_t *serverId, const char *cacertFile, const char *serverName) {
  if (connectionIsOpen) NetworkAdapters_CloseLog(*serverId);
  *serverId = 0;
  if (cacertFile != NULL && serverName != NULL) {
    connectionIsDtls = true;
    bool ret = DTLS_ClientInit(cacertFile, serverIpStr, port, serverName);
    if (ret) connectionIsOpen = true;
    return ret;
  }
  lwipv4_socket_init();
  udpSysLog = UDPSyslog::getInstance();
  // synchronization is too complex, so direct call will be used
  // mbed::util::FunctionPointer2<void, const char *, int16_t> fp(udpSysLog, &UDPSyslog::init);
  // minar::Scheduler::postCallback(fp.bind(serverIpStr, port));
  int16_t ret = udpSysLog->init(serverIpStr, port);
  if (ret) connectionIsOpen = true;
  return ret;
}

bool NetworkAdapters_SendData(int16_t serverId, const char *str, int16_t sLen) {
  (void)serverId;
  (void)sLen;
  if (connectionIsOpen == false) {
    snprintf(errStr, sizeof(errStr), "The connection must be set first");
    return false;
  }
  if (connectionIsDtls) {
    return DTLS_ClientSendPacket((const uint8_t *)str, sLen);
  }
  udpSysLog->onSend(str);
  return true;
}

bool NetworkAdapters_CloseLog(int16_t serverId) {
  (void)serverId;
  if (connectionIsDtls) {
    DTLS_ClientFree();
    connectionIsOpen = false;
    connectionIsDtls = false;
  } else {
    //	udpSysLog->close();
    // connectionIsOpen = false;
    snprintf(errStr, sizeof(errStr), "Log was already closed");
    return false;
  }
  return true;
}

#else

bool NetworkAdapters_SetIpToHostName(char hostName[MAX_HOST_NAME]) {
  strncpy(hostName, "Test", MAX_HOST_NAME);
  return false;
}

bool NetworkAdapters_GetMacAddress(unsigned char mac[MAC_ADDRESS_LEN]) {
  memcpy(mac, "mac-t", MAC_ADDRESS_LEN);
  return false;
}

bool NetworkAdapters_OpenClient(const char *serverIpStr, int16_t port, int16_t *serverId, const char *cacertFile, const char *serverName) {
  *serverId = 0;
  connectionIsOpen = true;
  return true;
}

bool NetworkAdapters_SendData(int16_t serverId, const char *str, int16_t sLen) {
  printf("log data: %s (len %d)\r\n", str, sLen);
  return true;
}

bool NetworkAdapters_CloseLog(int16_t serverId) {
  (void)serverId;
  printf("close %d\n", serverId);
  connectionIsOpen = false;
  connectionIsDtls = false;
  return true;
}

#endif
}
