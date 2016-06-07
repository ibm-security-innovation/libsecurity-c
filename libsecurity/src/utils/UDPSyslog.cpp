#ifdef MBED_OS

#include "libsecurity/utils/UDPSyslog.h"

UDPSyslog::UDPSyslog() : sock(SOCKET_STACK_LWIP_IPV4), _addressWasSet(FALSE), _udpSyslogPort(UDP_SYSLOG_PORT) {
  int16_t ret = 0;
  ret = _eth.init();
  if (ret != 0) {
    printf("Error while try to initialize Ethernet, error %d\n", ret);
  }
  ret = _eth.connect();
  if (ret != 0) {
    printf("Error while try to connect to Ethernet, error %d\n", ret);
  }
  printf("UDP client IP Address is %s\n", _eth.getIPAddress());

  ret = sock.open(SOCKET_AF_INET4);
  if (ret != 0) {
    printf("Error while try to open socket, error %d\n", ret);
  }
}

int16_t UDPSyslog::init(const char *addressStr, int16_t port) {
  struct socket_addr sa;
  int32_t addr = 0;
  int16_t addrVec[4];

  if (Utils_GetIpV4Address(addressStr, addrVec, &addr) == FALSE) return FALSE;
  socket_addr_set_ipv4_addr(&sa, addr);
  _resolvedAddr.setAddr(&sa);
  _addressWasSet = TRUE;
  _udpSyslogPort = port;
  return TRUE;
}

int16_t UDPSyslog::onSend(const char *text) {
  return sendSyslogMessage(&sock, text);
}

uint16_t UDPSyslog::getSyslogPort() {
  return _udpSyslogPort;
}

int16_t UDPSyslog::close() {
  return TRUE;
//  _eth.disconnect();
//  return sock.close();
}

int16_t UDPSyslog::sendSyslogMessage(Socket *s, const char *msg) {
  if (_addressWasSet == FALSE) {
    printf("Address was not set, set it first\n");
    snprintf(errStr, sizeof(errStr), "Address was not set, set it first");
    return FALSE;
  }
  char buf[32];
  _resolvedAddr.fmtIPv4(buf, 32);
  int16_t len = strlen(msg);
  printf("Sending syslog to %s:%d message: '%s' (len %d)\n", buf, (int16_t)_udpSyslogPort, msg, len);
  socket_error_t err = s->send_to(msg, len, &_resolvedAddr, _udpSyslogPort);
  if (err != SOCKET_ERROR_NONE) {
    printf("Socket Error %d\n", err);
    snprintf(errStr, sizeof(errStr), "Socket Error %d\n", err);
    return FALSE;
  }
  return TRUE;
}

#endif