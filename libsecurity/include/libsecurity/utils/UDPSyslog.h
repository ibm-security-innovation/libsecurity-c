#ifdef MBED_OS
#include "mbed-drivers/mbed.h"
#include "EthernetInterface.h"
#include "sockets/UDPSocket.h"
#include "sal/socket_api.h"
#include "minar/minar.h"
#include "core-util/FunctionPointer.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sal-stack-lwip/lwipv4_init.h"

#include "libsecurity/utils/utils.h"

using namespace mbed::Sockets::v0;

#define UDP_SYSLOG_PORT 514

#define ief_check()

class UDPSyslog {

  // protected:
  //	UDPSyslog();

  private:
  UDPSocket sock;
  EthernetInterface _eth;
  SocketAddr _resolvedAddr;
  bool _addressWasSet;
  uint16_t _udpSyslogPort;

  int16_t sendSyslogMessage(Socket *s, const char *msg);

  public:
  static UDPSyslog *_pInstance;

  UDPSyslog();
  static UDPSyslog *getInstance() {
    if (!_pInstance) {
      _pInstance = new UDPSyslog();
    }
    return _pInstance;
  }

  int16_t init(const char *addressStr, int16_t port);
  int16_t onSend(const char *text);
  uint16_t getSyslogPort();
  int16_t close(void);
};

#endif
