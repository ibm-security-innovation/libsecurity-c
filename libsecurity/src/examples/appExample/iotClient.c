#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#include "libsecurity/utils/utils_int.h"
#include "libsecurity/utils/sysLog_int.h"
#include "libsecurity/utils/hwAdapters.h"

//static char serverHostStr[100] = "127.0.0.1";
static char serverHostStr[100] = "9.147.6.106";
static char serverPortStr[6] = "8514";
static char intervalStr[6] = "1";
static char minRndStr[4] = "10";
static char maxRndStr[4] = "20";
static char baseValStr[4] = "1";
static char highValStr[4] = "100";
static char baseValIntervalStr[3] = "3";
static char highValIntervalStr[3] = "1";
static char logIntervalLenStr[3] = "4";
static char totalPacketsStr[100] = "10";

static char *cacertFile = "./cacert.pem";
static char *appName = "IoTClient";
static char *mulePath = "a.b.c.d";
static char *logMessageStr = "Someone open the door";
static int muleMessageType = 1, minRnd = 1, maxRnd = 10;

void printUsage() {
  printf("Usage: %s\n", appName);
  printf("    -h server_host_ip (default %s)\n", serverHostStr);
  printf("    -p server_port (default %s)\n", serverPortStr);
  printf("    -i interval_in_sec (default %s sec)\n", intervalStr);
  printf("    -b base_val (default %s)\n", baseValStr);
  printf("    -f high_val (default %s)\n", highValStr);
  printf("    -m min_random_val (default %s)\n", minRndStr);
  printf("    -x max_random_val (default %s)\n", maxRndStr);
  printf("    -s intervals_of_base_values (default %s)\n", baseValIntervalStr);
  printf("    -e intervals_of_high_values (default %s)\n", highValIntervalStr);
  printf("    -l number_of_intervals_between_log_messages (default %s)\n", logIntervalLenStr);
  printf("    -t total_number_of_packets_to_send (default %s, 0=infinit)\n", totalPacketsStr);
  printf("    -H this help\n");
}

void parseOptions(int argc, char **argv) {
  int opt;

  /* Parse command line */
  while ((opt = getopt(argc, argv, "h:p:i:s:f:m:x:b:e:l:H")) != -1) {
    switch (opt) {
    case 'h':
      strncpy(serverHostStr, optarg, sizeof(serverHostStr));
      break;
    case 'p':
      strncpy(serverPortStr, optarg, sizeof(serverPortStr));
      break;
    case 'i':
      strncpy(intervalStr, optarg, sizeof(intervalStr));
      break;
    case 'm':
      strncpy(minRndStr, optarg, sizeof(minRndStr));
      break;
    case 'x':
      strncpy(maxRndStr, optarg, sizeof(maxRndStr));
      break;
    case 'b':
      strncpy(baseValStr, optarg, sizeof(baseValStr));
      break;
    case 'f':
      strncpy(highValStr, optarg, sizeof(highValStr));
      break;
    case 's':
      strncpy(baseValIntervalStr, optarg, sizeof(baseValIntervalStr));
      break;
    case 'e':
      strncpy(highValIntervalStr, optarg, sizeof(highValIntervalStr));
      break;
    case 'l':
      strncpy(logIntervalLenStr, optarg, sizeof(logIntervalLenStr));
      break;
    case 't':
      strncpy(totalPacketsStr, optarg, sizeof(totalPacketsStr));
      break;
    case 'H':
    default: /* '?' */
      printUsage();
      exit(0);
    }
  }
}

void initConnection() {
  int16_t port = atoi(serverPortStr);

  printf("The ca cert file name '%s'\n", cacertFile);
  Syslog_UpdateHostNameType(SYSLOG_USE_IP_ADDRESS_AS_HOST_IDX);
  Syslog_UpdateAppName(appName);
  if (Syslog_OpenLog(serverHostStr, port, cacertFile, serverHostStr) == false) {
    printf("Fatal error: initConnection, error %s\n", errStr);
    exit(-1);
  }
}

static int generateMeterReading(int baseValue) {
  const int64_t cycle = 801;
  const double span = 10.0;
  time_t t = time(NULL);
  const int64_t v = t % cycle;
  const double pi = 4.0 * atan(1.0);
  double sinval = sin(((double)v / (double)cycle) * (2 * pi));
  return baseValue + (int)(sinval * span) + ((rand() + minRnd) % maxRnd);
}

bool sendMessageToMule(int val) {
  int value = generateMeterReading(val);
  if (Syslog_Mule(muleMessageType, mulePath, value) == false)
    printf("sendMessageToMule Error: %s\n", errStr);
  return true;
}

bool sendLogMessage() {
  if (Syslog_Log(SevirityError, logMessageStr) == false)
    printf("sendLogMessage Error: %s\n", errStr);
  return true;
}

void closeConnection() { Syslog_CloseLog(); }

void loop() {
  int idx = 0, delay = atoi(intervalStr), logInterval = atoi(logIntervalLenStr), totalPackets = atoi(totalPacketsStr);
  int intervalLen = atoi(baseValIntervalStr) + atoi(highValIntervalStr);
  int baseInterval = atoi(baseValIntervalStr);
  int baseVal = atoi(baseValStr), highVal = atoi(highValStr);
  
  minRnd = atoi(minRndStr);
  maxRnd = atoi(maxRndStr);

  initConnection();
  while (idx < totalPackets && totalPackets != 0) {
    if ((idx++ % intervalLen) < baseInterval)
      sendMessageToMule(baseVal);
    else
      sendMessageToMule(highVal);
    if (idx % logInterval == 0) {
      sendLogMessage();
      printf(".");
      fflush(stdout);
      HwAdapters_Sleep(delay, 0);
    }
  }
  closeConnection();
}

#ifdef MBED_OS
int iotClient() {
  int argc = 0 ;
  char **argv = NULL;
#else
int main(int argc, char **argv) {
#endif  
  srand(time(NULL));

  parseOptions(argc, argv);
  printf("Values: server IP '%s', port '%s', totla number of packets %s, interval '%s', min rnd '%s', max "
         "rnd '%s', base value '%s' high value '%s', base interval '%s', high "
         "interval '%s', log interval '%s'\n",
         serverHostStr, serverPortStr, totalPacketsStr, intervalStr, minRndStr, maxRndStr,
         baseValStr, highValStr, baseValIntervalStr, highValIntervalStr,
         logIntervalLenStr);
  printf("Note: Don't forget to run goldy first\n");
  Syslog_SetDtls(true);
  loop();
  return 1;
}
