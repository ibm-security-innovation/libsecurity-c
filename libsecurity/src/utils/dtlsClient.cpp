//extern int make_iso_compilers_happy; // gcc when compiled with -pedantic reports a diagnostic when the translation unit is empty as it is requested by the C Standard

#include "libsecurity/utils/dtlsClient_int.h"

#if defined(MBED_OS)

// use the K64F random number generator
bool DTLS_GetRandom(unsigned char *random, int16_t len) {
  uint32_t val = 0;
#define RNG_BASE (0x40029000u)
  SIM_SCGC6 |= SIM_SCGC6_RNGA_MASK; // turn on RNGA
  RNG_CR &= ~RNG_CR_SLP_MASK; // set SLP bit to 0 (not in sleep mode)
  RNG_CR |= RNG_CR_HA_MASK;
  RNG_CR |= RNG_CR_GO_MASK;
  while ((RNG_SR & RNG_SR_OREG_LVL(0xF)) == 0) {
  } // wait for RNG FIFO to be full
  val = RNG_OR;
  snprintf((char *)random, len, "%lu", val);
  return true;
}

using namespace mbed::Sockets::v0;

class UDPConnect {
  public:
  UDPConnect(const char *serverAddrStr, uint16_t port) : sock(SOCKET_STACK_LWIP_IPV4), serverAddrStr(serverAddrStr), port(port) {
    sock.open(SOCKET_AF_INET4);

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ssl_ctr_drbg);
    mbedtls_entropy_init(&ssl_entropy);
  }

  virtual ~UDPConnect() {
    close();
    mbedtls_entropy_free(&ssl_entropy);
    mbedtls_ctr_drbg_free(&ssl_ctr_drbg);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_ssl_free(&ssl);
  }

  bool setup(const char *serverName) {
    const char *pers = "libsecurity";
    int ret;
    if ((ret = mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
      snprintf(errStr, sizeof(errStr), "mbedtls_ssl_config_defaults fail");
      return false;
    }
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL); // Fix it

    ret = mbedtls_x509_crt_parse(&cacert, SERVER_CERT, sizeof(SERVER_CERT));
    if (ret != 0) {
      snprintf(errStr, sizeof(errStr), "setup: mbedtls_x509_crt_parse returned %d", ret);
      DTLS_ClientFree();
      return false;
    }
    ret = mbedtls_ctr_drbg_seed(&ssl_ctr_drbg, mbedtls_entropy_func, &ssl_entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
      snprintf(errStr, sizeof(errStr), "mbedtls_ctr_drbg_seed fail");
      return false;
    }
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ssl_ctr_drbg); // ??? random generator in mbed?

    ret = mbedtls_ssl_setup(&ssl, &ssl_conf);
    if (ret != 0) {
      snprintf(errStr, sizeof(errStr), "mbedtls_ssl_setup fail");
      return false;
    }

    if (serverName != NULL) {
      ret = mbedtls_ssl_set_hostname(&ssl, serverName);
      if (ret != 0) {
        snprintf(errStr, sizeof(errStr), "mbedtls_ssl_set_hostname fail");
        return false;
      }
    }

    mbedtls_ssl_set_timer_cb(&ssl, &timer, static_timing_set_delay, static_timing_get_delay);
    mbedtls_ssl_set_bio(&ssl, this, static_udp_send, static_udp_recv, NULL);

    mbed::Sockets::v0::SocketAddr sock_addr;
    sock_addr.setAddr(SOCKET_AF_INET4, serverAddrStr);
    sock.connect(&sock_addr, port);
    do {
      ret = mbedtls_ssl_handshake(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret != 0) {
      snprintf(errStr, sizeof(errStr), "mbedtls_ssl_handshake fail");
      return false;
    }
    // TODO mbedtls_ssl_get_verify_result(&ssl) and report errors;
    return true;
  }

  bool sendPacket(const uint8_t *body, const size_t body_len) {
    int ret;
    do {
      ret = mbedtls_ssl_write(&ssl, body, body_len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret < 0) {
      return false;
    }
    return true;
  }

  bool close() {
    int ret;
    /* No error checking, the connection might be closed already */
    do {
      ret = mbedtls_ssl_close_notify(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    sock.close();
    return true;
  }

  socket_error_t send(const uint8_t *buf, int16_t len) {
    _serverAddr.setAddr(SOCKET_AF_INET4, serverAddrStr);
    socket_error_t err = this->sock.send_to(buf, len, &_serverAddr, port);
    return err;
  }

  socket_error_t recv(unsigned char *buf, size_t *len_ptr) {
    socket_error_t err = this->sock.recv(buf, len_ptr);
    return err;
  }

  protected:
  // Receive callback for mbed TLS
  static int static_udp_recv(void *ctx, unsigned char *buf, size_t len) {
    UDPConnect *conn = static_cast<UDPConnect *>(ctx);
    socket_error_t err = conn->recv(buf, &len);
    if (err == SOCKET_ERROR_NONE) {
      return static_cast<int>(len);
    } else if (err == SOCKET_ERROR_WOULD_BLOCK) {
      return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
      return -1;
    }
  }

  // Send callback for mbed TLS
  static int static_udp_send(void *ctx, const unsigned char *buf, size_t len) {
    UDPConnect *conn = static_cast<UDPConnect *>(ctx);
    socket_error_t err = conn->send(buf, len);
    if (err == SOCKET_ERROR_NONE) {
      return static_cast<int>(len);
    } else if (err == SOCKET_ERROR_WOULD_BLOCK) {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    } else {
      return -1;
    }
  }

  // for DTLS over UDP, it is only a stub
  static void static_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms) {
    (void)data;
    (void)int_ms;
    (void)fin_ms;
  }

  // for DTLS over UDP, it is only a stub
  static int static_timing_get_delay(void *data) {
    (void)data;
    return 1;
  }

  public:
  UDPSocket sock;

  private:
  SocketAddr _serverAddr;
  const char *serverAddrStr;
  const uint16_t port;
  mbedtls_x509_crt cacert;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config ssl_conf;
  mbedtls_entropy_context ssl_entropy;
  mbedtls_ctr_drbg_context ssl_ctr_drbg;
  mbedtls_timing_delay_context timer;
};

EthernetInterface *eth;
UDPConnect *gt;
bool clientWasInit = false;

bool DTLS_ClientInit(const char *cacertFile, const char *serverAddr, int16_t port, const char *serverName) {
  (void)cacertFile;

  if (clientWasInit) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: client was already initialized, you must free it first");
    return false;
  }
  if (serverAddr == NULL) return false;
  // get_stdio_serial().baud(115200);

  NetworkAdapters_GetEth((void **)&eth);
  lwipv4_socket_init();
  // printf("UDP client IP Address is %s\n", (*eth).getIPAddress());
  gt = new UDPConnect(serverAddr, port);
  bool ret = gt->setup(serverName);
  if (ret)
    clientWasInit = true;
  return ret;
}

bool DTLS_ClientSendPacket(const uint8_t *body, int len) {
  if (clientWasInit == false) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientSendPacket: client must be initialized first");
    return false;
  }
  return gt->sendPacket(body, len);
}

void DTLS_ClientFree() {
  if (clientWasInit == false) {
    return;
  }
  clientWasInit = false;
  gt->close();
  delete gt;
}

#else // mbed on LINUX_OS

extern "C" {

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt cacert;
static mbedtls_timing_delay_context timer;
static mbedtls_net_context server_fd;
static bool clientWasInit = false;

bool DTLS_ClientInit(const char *cacertFile, const char *serverAddr, int16_t port, const char *serverName) {
  const char *pers = "libsecurity";
  int16_t ret;
  uint32_t flags;
  char serverPort[SERVER_PORT_LEN];

  if (clientWasInit) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: client was already initialized, you must free it first");
    return false;
  }
  snprintf(serverPort, sizeof(serverPort), "%d", port);
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_init(&entropy);
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: mbedtls_ctr_drbg_seed returned %d", ret);
    DTLS_ClientFree();
    return false;
  }
  if (cacertFile && cacertFile[0]) {
    ret = mbedtls_x509_crt_parse_file(&cacert, cacertFile);
    if (ret != 0) {
      snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: mbedtls_x509_crt_parse returned %d", ret);
      DTLS_ClientFree();
      return false;
    }
  } else {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: CA is not set");
    return false;
  }
  if ((ret = mbedtls_net_connect(&server_fd, serverAddr, serverPort, MBEDTLS_NET_PROTO_UDP)) != 0) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: mbedtls_net_connect returned %d", ret);
    DTLS_ClientFree();
    return false;
  }
  if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: mbedtls_ssl_config_defaults returned %d", ret);
    DTLS_ClientFree();
    return false;
  }
  // fix it
  /* OPTIONAL is usually a bad choice for security, but makes interop easier
   * in this simplified example, in which the ca chain is hardcoded.
   * Production code should set a proper ca chain and use REQUIRED. */
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: mbedtls_ssl_setup returned %d", ret);
    DTLS_ClientFree();
    return false;
  }

  if ((ret = mbedtls_ssl_set_hostname(&ssl, serverName)) != 0) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: mbedtls_ssl_set_hostname returned %d", ret);
    DTLS_ClientFree();
    return false;
  }
  mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
  do
    ret = mbedtls_ssl_handshake(&ssl);
  while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret != 0) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: mbedtls_ssl_handshake returned 0x%x", ret);
    return false;
  }
  /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
   * handshake would not succeed if the peer's cert is bad.  Even if we used
   * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
  if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
    char vrfy_buf[512];
    mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
    snprintf(errStr, sizeof(errStr), "DTLS_ClientInit: Failed verifying peer X.509 certificate: %s", vrfy_buf);
  }
  clientWasInit = true;
  return true;
}

bool DTLS_ClientSendPacket(const uint8_t *body, int body_len) {
  int16_t ret;

  if (clientWasInit == false) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientSendPacket: client must be initialized first");
    return false;
  }
  do
    ret = mbedtls_ssl_write(&ssl, body, body_len);
  while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  if (ret < 0) {
    snprintf(errStr, sizeof(errStr), "DTLS_ClientSendPacket: mbedtls_ssl_write returned %d", ret);
    return false;
  }
  return true;
}

void DTLS_ClientFree() {
  int16_t ret;

  if (clientWasInit == false) {
    return;
  }

  /* No error checking, the connection might be closed already */
  do
    ret = mbedtls_ssl_close_notify(&ssl);
  while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  mbedtls_net_free(&server_fd);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  clientWasInit = false;
}
}

#endif
