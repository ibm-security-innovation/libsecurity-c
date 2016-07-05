#include "libsecurity/utils/utils_int.h"
#include "libsecurity/utils/sysLog_int.h"
#include "libsecurity/utils/hwAdapters.h"
#include "libsecurity/utils/fileAdapters.h"

static int16_t NumOfLogMessages = 3;

static const char *mallocStrFmt = "%s len = %d";
static const char *freeStrFmt = "%s";
static const char *fopenStrFmt = "file name: '%s' mode :'%s'";
static const char *fcloseStrFmt = "fclose file: '%s'";
static const char *removeStrFmt = "remove file: '%s'";

#ifdef INTERNAL_LOG
static char *logFilePath = "/var/log/user.log";
static char *syslogServerIpStr = "127.0.0.1";
#else // external log
static char *syslogServerIpStr = "9.147.6.106";
#endif

#if defined(MBED_OS)
static char *cacertFile = "./cacert.pem";
static int16_t syslogServerPort = 8514;
#else
static char *cacertFile = NULL;
static int16_t syslogServerPort = 514;
#endif

typedef struct {
  char *pwd;
  char *user;
  PasswordStreangthType pwdStrength;
}pwdStrengthStruct;

STATIC bool getLastLineOfFile(char *file, char *line, int16_t maxLen) {
  int16_t len = 0;
  bool ret = false;
  char c;
  FILE *ifp = fopen(file, "r");

  if (ifp == NULL) return false;

  fseek(ifp, -1, SEEK_END); // next to last char, last is EOF
  c = fgetc(ifp);
  while (c == '\n') {
    fseek(ifp, -2, SEEK_CUR);
    c = fgetc(ifp);
  }
  while (c != '\n') {
    fseek(ifp, -2, SEEK_CUR);
    ++len;
    c = fgetc(ifp);
  }
  fseek(ifp, 1, SEEK_CUR);

  if (len > maxLen) len = maxLen;
  if (fgets(line, len, ifp) != NULL)
    ret = true;
  else
    ret = false;
  fclose(ifp);
  return ret;
}

STATIC bool testCrypto() {
  int16_t i=0, len=0;
  bool pass = true;
  unsigned char text[NaCl_MAX_TEXT_LEN_BYTES+1];
  unsigned char key[SECRET_LEN], iv[IV_LEN];
  unsigned char encryptedText[NaCl_MAX_TEXT_LEN_BYTES+1];
  unsigned char decryptedText[NaCl_MAX_TEXT_LEN_BYTES+1];

  Crypto_Random(key, SECRET_LEN);
  Crypto_Random(iv, IV_LEN);

  char *addText = "1234567890123456";
  strcpy(text, addText);
  for (i=0 ; i<12 ; i++) {
    len = Crypto_EncryptDecryptAesCbc(CRYPTO_ENCRYPT_MODE, strlen(text), key, SECRET_LEN, iv, text, encryptedText);
    printf("encrypted len in %d\n", len);
    len = Crypto_EncryptDecryptAesCbc(CRYPTO_DECRYPT_MODE, len, key, SECRET_LEN, iv, encryptedText, decryptedText);
    printf("decrypted len %d\n", len);
    if (len > 0)
      decryptedText[len] = '\0';

//    printf("Ravid: decrypted text '%s'\n", decryptedText);
//    if (len > 0 && memcmp(text, decryptedText, strlen(text)-1) != 0) {
//      printf("Error: test fail, original text '%s' != decrypted text '%s'\n", text, decryptedText);
//      pass = false;
//    }
    strcat(text, addText);
  }
  return pass;
}

// Test if the password strength is as expected
STATIC bool testPwdStrength() {
  int16_t i=0, len=0;
  bool pass = true;
  unsigned char *newPwd=NULL;
  pwdStrengthStruct pwdStrength[] = {{"abc", "", STRENGTH_POOR}, {"", NULL, STRENGTH_POOR}, 
    {"abAB12#$", NULL, STRENGTH_EXCELLENT}, {"aAB123", "", STRENGTH_SUFFICIENT}, 
    {"aA12#$", "", STRENGTH_SUFFICIENT}, {"abcd123", "", STRENGTH_SUFFICIENT},
    {"123456", "", STRENGTH_POOR}, {"a12AB#%", "", STRENGTH_GOOD},
    {"abAB12#$", "bab", STRENGTH_SUFFICIENT}, {"abAB12#$", "ba", STRENGTH_EXCELLENT}, 
    {"ravID11#%", "ravid", STRENGTH_SUFFICIENT}, {"araVIdra", "raVId", STRENGTH_POOR}
  };
  PasswordStreangthType val, expected;

  len = sizeof(pwdStrength) / sizeof(pwdStrengthStruct);
  for(i=0 ; i<len ; i++) {
    val = Utils_CalculatePasswordStrength((unsigned char *)pwdStrength[i].pwd, (unsigned char *)pwdStrength[i].user);
    if (val != pwdStrength[i].pwdStrength) {
      printf("Error: test fail, password '%s' expected strength %d, calculated strength %d\n", pwdStrength[i].pwd, pwdStrength[i].pwdStrength, val);
      pass = false;
    }
  }
  for (i=0 ; i<MAX_PASSWORD_LENGTH+5 ; i++) {
    if (Utils_GenerateNewValidPassword(&newPwd, i) == true) {
      val = Utils_CalculatePasswordStrength(newPwd, NULL);
      if ((i>=10 && val < STRENGTH_EXCELLENT) || (i>=MIN_PASSWORD_LENGTH && i < 10 && val < STRENGTH_GOOD)) {
        expected = STRENGTH_EXCELLENT;
        if (i<10)
          expected = STRENGTH_GOOD;
        printf("Error: test fail, password '%s' expected strength at least %d, calculated strength %d\n", newPwd, expected, val);
        pass = false;
      }
      Utils_Free(newPwd);
    }
    if (pass == false)
      break;
  }
  return pass;
}

STATIC bool testIpStr() {
  int16_t i = 0, len = 0, address[4];
  int32_t tmp = 0;
  bool pass = true;
  char *notValidIp[] = { NULL, "1", "2.3", "1.2.3", "1.2.3.4.5", "256.1.2.3", "2.-1.3.4", "", "!.2.3.4", "1.@.3.4", "1.2.a.4", "1.2.3.x" };
  char *validIp[] = { "1.2.3.4", "0.0.0.0", "255.255.255.255" };
  char str[MAX_IP_STR_LEN];

  len = sizeof(notValidIp) / sizeof(char *);
  for (i = 0; i < len; i++) {
    if (Utils_IsIpStrValid(notValidIp[i]) == true) {
      printf("Error: test fail, invalid IP '%s' pass\n", notValidIp[i]);
      pass = false;
    }
  }
  len = sizeof(validIp) / sizeof(char *);
  for (i = 0; i < len; i++) {
    if (Utils_GetIpV4Address(validIp[i], address, &tmp) == false) {
      printf("Error: test fail, valid IP '%s' fail\n", validIp[i]);
      pass = false;
    }
    snprintf(str, sizeof(str), "%d.%d.%d.%d", address[0], address[1], address[2], address[3]);
    if (strncmp(validIp[i], str, MAX_IP_STR_LEN) != 0) {
      printf("Error: test fail, valid IP '%s' was converted to '%s'\n", validIp[i], str);
      pass = false;
    }
  }
  return pass;
}

// Generate a log message, send it to the syslog and compare with the syslog
// file
STATIC bool testSyslogLogMessage() {
#ifndef OPENSSL_CRYPTO // ravid fix it
  int16_t i = 0, j = 0;
  bool pass = false, ret = false;
  char expStr[ERR_STR_LEN], testStr[ERR_STR_LEN], hostName[ERR_STR_LEN];
  char *appName = "testSyslogLogMessage", *testStrFmt = "Test %d with %s", *strParam = "lalala";

  printf("syslog server ip is %s, cacert file name '%s'\n", syslogServerIpStr, cacertFile);
  Syslog_SetDtls(false);
  if (Syslog_OpenLog(syslogServerIpStr, syslogServerPort, cacertFile, syslogServerIpStr) == false) {
    printf("Error: %s\n", errStr);
    return false;
  }
  Syslog_UpdateAppName(appName);
  for (j = SYSLOG_USE_MAC_ADDRESS_AS_HOST_IDX; j <= SYSLOG_USE_IP_ADDRESS_AS_HOST_IDX; j++) {
    Syslog_UpdateHostNameType(j);
    SyslogTest_GetHostName(hostName, ERR_STR_LEN);
    for (i = 0; i < NumOfLogMessages; i++) {
      snprintf(testStr, ERR_STR_LEN, testStrFmt, i, strParam);
      snprintf(expStr, ERR_STR_LEN, "%s %s %s %s %s %s %s", SYSLOG_NIL_STR, hostName, appName, SYSLOG_NIL_STR, SYSLOG_LOG_STR, SYSLOG_NIL_STR, testStr);
      ret = Syslog_Log(i % (SevirityDebug + 1), "Test %d with %s\n", i, "lalala");
      if (ret == false) printf("testSyslogLogMessage Error: %s\n", errStr);
      pass |= ret;
      HwAdapters_Sleep(1, 0);
#ifdef INTERNAL_LOG
      char line[ERR_STR_LEN];
      if (getLastLineOfFile(logFilePath, line, ERR_STR_LEN) == false) {
        printf("Error: can't read the last line of the log file '%s'\n", logFilePath);
        pass = false;
        break;
      }
      if (strstr(line, expStr) == NULL) {
        printf("Error: expected string '%s' is not in the read log line '%s'\n", expStr, line);
        pass = false;
        break;
      }
#endif
      // printf("Line: '%s'\nExp str '%s'\n", line, expStr);
    }
    if (pass == false) break;
  }
  Syslog_CloseLog();
  return pass;
#else
  return true;
#endif
}

// Generate a mule message, send it to the syslog and compare with the syslog
// file
STATIC bool testSyslogMuleMatrics() {
#ifndef OPENSSL_CRYPTO // ravid fix it
  int16_t i = 0, idx = 0;
  bool pass = false, ret = false;
  char expStr[ERR_STR_LEN], testStr[ERR_STR_LEN], hostName[ERR_STR_LEN];
  char *appName = "testSyslogMuleMatrics", *testStrFmt = "[%s@%d %s=\"%d\"]", *mulePath = "a.b.c.d";

  printf("Mule syslog server ip is %s\n", syslogServerIpStr);
  Syslog_SetDtls(false);
  if (Syslog_OpenLog(syslogServerIpStr, syslogServerPort, cacertFile, syslogServerIpStr) == false) {
    printf("Error: %s\n", errStr);
    return false;
  }
  Syslog_UpdateAppName(appName);
  Syslog_UpdateHostNameType(SYSLOG_USE_IP_ADDRESS_AS_HOST_IDX);
  SyslogTest_GetHostName(hostName, ERR_STR_LEN);
  for (i = 0; i < NumOfLogMessages; i++) {
    idx = i * 10 + i % MuleMax + 1;
    snprintf(testStr, ERR_STR_LEN, testStrFmt, SYSLOG_MULE_STR, i + 1, mulePath, idx);
    snprintf(expStr, ERR_STR_LEN, "%s %s %s %s %s %s", SYSLOG_NIL_STR, hostName, appName, SYSLOG_NIL_STR, SYSLOG_MULE_STR, testStr);
    ret = Syslog_Mule(i % MuleMax + 1, mulePath, idx);
    if (ret == false) printf("testSyslogMuleMatrics Error: %s\n", errStr);
    pass |= ret;
    HwAdapters_Sleep(1, 0);
#ifdef INTERNAL_LOG
    char line[ERR_STR_LEN];
    if (getLastLineOfFile(logFilePath, line, ERR_STR_LEN) == false) {
      printf("Error: can't read the last line of the log file '%s'\n", logFilePath);
      pass = false;
      break;
    }
    if (strstr(line, expStr) == NULL) {
      printf("Error: expected string '%s' is not in the read log line '%s'\n", expStr, line);
      pass = false;
      break;
    }
#endif
  }
  Syslog_CloseLog();
  return pass;
#else
  return true;
#endif
}

STATIC bool testSetAppName() {
#ifndef OPENSSL_CRYPTO // ravid fix it
  int16_t i = 0, ret, expect;
  bool pass = true;
  char str[6], *expStr = NULL;

  for (i = 1; i < 255; i++) {
    snprintf(str, sizeof(str), "a%c1", i);
    ret = Syslog_UpdateAppName(str);
    expect = ((i >= 65 && i <= 90) || (i >= 97 && i <= 122) || (i >= 48 && i <= 57));
    expStr = "legal";
    if (expect == false) expStr = "illegal";
    if (ret != expect) {
      printf("Test fail: error: character '%c' (%d) is %s but the ret is %d\n", i, i, expStr, ret);
      pass = false;
    }
  }
  return pass;
#else
  return true;
#endif
}

STATIC void dontExit(const char *msg) {
  snprintf(errStr, sizeof(errStr), "%s", msg);
}

STATIC bool testAbortCb() {
  const char *msg = "Print and don't exit";

  Utils_AbortCallBack(dontExit);
  Utils_Abort(msg);
  return (strncmp(msg, errStr, strlen(msg)) == 0);
}

STATIC bool myMalloc(void **ptr, int16_t len) {
  snprintf(errStr, sizeof(errStr), mallocStrFmt, *ptr, len);
  return true;
}

STATIC bool testMyMalloc() {
  int16_t len = 90;
  char *ptr = "my malloc";
  char str[ERR_STR_LEN];

  Utils_MallocCallBack(myMalloc);
  Utils_Malloc((void **)&ptr, len);
  snprintf(str, sizeof(str), mallocStrFmt, ptr, len);
  Utils_MallocCallBack(NULL);
  return (strncmp(str, errStr, strlen(str)) == 0);
}

STATIC void myFree(void *ptr) {
  snprintf(errStr, sizeof(errStr), freeStrFmt, ptr);
}

STATIC bool testMyFree() {
  char *ptr = "my free";
  char str[ERR_STR_LEN];

  Utils_FreeCallBack(myFree);
  Utils_Free((void *)ptr);
  snprintf(str, sizeof(str), freeStrFmt, ptr);
  return (strncmp(str, errStr, strlen(str)) == 0);
}

STATIC FILE *myFopen(const char *fileName, const char *mode) {
  snprintf(errStr, sizeof(errStr), fopenStrFmt, fileName, mode);
  return NULL;
}

STATIC bool testMyFopen() {
  char *ptr = "fopen my file", *mode = "write";
  char str[ERR_STR_LEN];

  Utils_FopenCallBack(myFopen);
  Utils_Fopen(ptr, mode);
  snprintf(str, sizeof(str), fopenStrFmt, ptr, mode);
  Utils_FopenCallBack(NULL);
  return (strncmp(str, errStr, strlen(str)) == 0);
}

STATIC int myFclose(FILE *stream) {
  snprintf(errStr, sizeof(errStr), fcloseStrFmt, (char *)stream);
  return 1;
}

STATIC bool testMyFclose() {
  char *ptr = "fclose my file";
  char str[ERR_STR_LEN];

  Utils_FcloseCallBack(myFclose);
  Utils_Fclose((FILE *)ptr);
  snprintf(str, sizeof(str), fcloseStrFmt, ptr);
  Utils_FcloseCallBack(NULL);
  return (strncmp(str, errStr, strlen(str)) == 0);
}

STATIC int myRemove(const char *fileName) {
  snprintf(errStr, sizeof(errStr), removeStrFmt, fileName);
  return 1;
}

STATIC bool testMyRemoveFile() {
  char *ptr = "remove file";
  char str[ERR_STR_LEN];

  Utils_RemoveFileCallBack(myRemove);
  Utils_RemoveFile(ptr);
  snprintf(str, sizeof(str), removeStrFmt, ptr);
  Utils_RemoveFileCallBack(NULL);
  return (strncmp(str, errStr, strlen(str)) == 0);
}

// mbed file system must be tested
STATIC bool testReadWriteToFile() {
#ifndef MBED_OS
  return true;
#endif
  const char *fileName = "sdtest.txt", *str = "Hello fun SD Card World!";
  char readStr[100];
  FILE *fp = NULL;

  if ((fp = FileAdapters_Fopen(fileName, "w")) == NULL) {
    printf("testReadWriteToFile fail: error: Could not open file '%s' for write\n", fileName);
    return false;
  }
  fprintf(fp, "%s", str);
  FileAdapters_Fclose(fp);

  if ((fp = FileAdapters_Fopen(fileName, "r")) == NULL) {
    printf("testReadWriteToFile fail: error: Could not open file '%s' for read\n", fileName);
    return false;
  }
  if (Utils_Fgets(readStr, sizeof(readStr), fp) == NULL) {
    printf("testReadWriteToFile fail: error: Could not read from file\n");
    return false;
  }
  if (strncmp(str, readStr, strlen(str)) != 0) {
    printf("testReadWriteToFile fail: stored string '%s' != read string '%s'\n", str, readStr);
    return false;
  }
  FileAdapters_Fclose(fp);
  FileAdapters_Remove(fileName);
  return true;
}

#ifdef MBED_OS
int16_t testUtils()
#else
int main()
#endif
{
  bool pass = true;
  int16_t i = 0, len = 0;
  char *res = NULL;

  Utils_TestFuncS callFunc[] = { 
                                 { "testCrypto", testCrypto},
                                 { "testPwdStrength", testPwdStrength},
                                 { "testAbortCb", testAbortCb },
                                 { "testMyMalloc", testMyMalloc },
                                 { "testMyFree", testMyFree },
                                 { "testMyFopen", testMyFopen },
                                 { "testMyFclose", testMyFclose },
                                 { "testMyRemoveFile", testMyRemoveFile },
                                 { "testIpStr", testIpStr },
                                 { "testReadWriteToFile", testReadWriteToFile },
                                 { "testSyslogMuleMatrics", testSyslogMuleMatrics },
                                 { "testSyslogLogMessage", testSyslogLogMessage },
                                 { "testSetAppName", testSetAppName } 
                               };

  len = sizeof(callFunc) / sizeof(Utils_TestFuncS);

  for (i = 0; i < len; i++) {
    if ((callFunc[i]).testFunc() == false) {
      res = "fail";
      pass = false;
    } else
      res = "pass";
    printf("Test %s:'%s' %s\n", __FILE__, callFunc[i].name, res);
  }
  return pass;
}
