#include "libsecurity/utils/utils_int.h"

char errStr[ERR_STR_LEN];

bool Utils_GetIpV4Address(const char *ipStr, int16_t addressVec[4], int32_t *addr) {
  int16_t num = 0, cnt = 0, len = 0, i = 0;
  char *token = NULL, str[MAX_IP_STR_LEN], tmpStr[MAX_IP_STR_LEN];

  *addr = 0;
  if (ipStr == NULL) {
    snprintf(errStr, sizeof(errStr), "IP must not be NULL");
    return false;
  }
  len = strlen(ipStr);
  if (len >= MAX_IP_STR_LEN) len = MAX_IP_STR_LEN - 1;
  memcpy(str, ipStr, len + 1);
  token = strtok((char *)str, ".");

  while (token) {
    num = atoi(token);
    snprintf(tmpStr, sizeof(tmpStr), "%d", num);
    if (strncmp(token, tmpStr, MAX_IP_STR_LEN) != 0) {
      snprintf(errStr, sizeof(errStr), "IP '%s' is not valid, it contains a not digit value", ipStr);
      return false;
    }

    if (num > 255 || num < 0) {
      snprintf(errStr, sizeof(errStr), "IP '%s' is not valid, it contains value not in range 0-255", ipStr);
      return false;
    }
    if (cnt < 4) addressVec[cnt] = num;
    token = strtok(NULL, ".");
    cnt++;
  }
  if (cnt != 4) {
    snprintf(errStr, sizeof(errStr), "IP '%s' is not valid, it contains %d (!=4) tokens", ipStr, cnt);
    return false;
  }
  *addr = 0;
  for (i = 3; i >= 0; i--) {
    *addr = *addr << 8;
    *addr += addressVec[i];
  }
  return true;
}

bool Utils_IsIpStrValid(const char *ipStr) {
  int16_t address[4];
  int32_t addr = 0;

  return Utils_GetIpV4Address(ipStr, address, &addr);
}

bool Utils_CheckNameValidity(const char *errStrPrefix, const char *name, int16_t minLen, int16_t maxLen) {
  return Utils_IsStringValid(NAME_STR, errStrPrefix, name, minLen, maxLen);
}

bool Utils_IsPrefixValid(const char *errStrPrefix, const char *prefix) {
  return Utils_IsStringValid(PREFIX_STR, errStrPrefix, prefix, MIN_PREFIX_LEN, MAX_PREFIX_LEN);
}

// Add a prefix before the error str
void Utils_AddPrefixToErrorStr(const char *str) {
  int16_t i = 0, len = 0, strLen = -1, errStrLen = -1;

  if (str == NULL || errStr == NULL) return;
  strLen = strlen(str);
  errStrLen = strlen(errStr);
  len = errStrLen + strLen;
  if (len > ERR_STR_LEN) len = ERR_STR_LEN;
  // I can't use memcpy: the method of cpy on the same string may varied
  for (i = len; i >= strLen; i--)
    errStr[i] = errStr[i - strLen];
  memcpy(&(errStr[0]), str, strLen);
  errStr[len] = 0;
}

bool Utils_CreateAndCopyString(char **dst, const char *src, const int16_t len) {
  if (len < 0 || src == NULL) {
    snprintf(errStr, sizeof(errStr), "can't copy when len (%d) < 0 or src is NULL", len);
    return false;
  }
  Utils_Malloc((void **)(dst), len + 1);
  memcpy(*dst, src, len + 1);
  return true;
}

bool Utils_CreateAndCopyUcString(unsigned char **dst, const unsigned char *src, int16_t len) {
  if (len < 0 || src == NULL) {
    snprintf(errStr, sizeof(errStr), "can't copy when len (%d) < 0 or src is NULL", len);
    return false;
  }
  Utils_Malloc((void **)(dst), len + 1);
  memcpy(*dst, src, len + 1);
  return true;
}

static void (*abort_cb)(const char *msg);

void Utils_AbortCallBack(void (*cb)(const char *msg)) {
  abort_cb = cb;
}

void Utils_Abort(const char *msg) {
  if (!msg) msg = "(libsecurity-c) system error";

  if (abort_cb)
    abort_cb(msg);
  else {
    perror(msg);
    abort();
  }
}

static bool (*mallocCallBack)(void **dst, int16_t len);

void Utils_MallocCallBack(bool (*cb)(void **dst, int16_t len)) {
  mallocCallBack = cb;
}

bool Utils_Malloc(void **dst, int16_t len) {
  if (mallocCallBack) {
    return mallocCallBack(dst, len);
  } else {
    if (len < 0) {
      snprintf(errStr, sizeof(errStr), "can't copy when len (%d) < 0", len);
      return false;
    }
    *dst = (void *)calloc(1, len);
    if (*dst == NULL) {
      Utils_Abort("FATAL: Internal Error: memory allocation fail\n");
    }
  }
  return true;
}

static void (*freeCallBack)(void *ptr);

void Utils_FreeCallBack(void (*cb)(void *ptr)) {
  freeCallBack = cb;
}

void Utils_Free(void *ptr) {
  if (freeCallBack) {
    freeCallBack(ptr);
    return;
  }
  if (ptr == NULL) {
    return;
  }
  free(ptr);
  ptr = NULL;
}

static FILE *(*fopenCallBack)(const char *fileName, const char *mode);

void Utils_FopenCallBack(FILE *(*cb)(const char *fileName, const char *mode)) {
  fopenCallBack = cb;
}

FILE *Utils_Fopen(const char *fileName, const char *mode) {
  if (fopenCallBack) {
    return fopenCallBack(fileName, mode);
  }
  return fopen(fileName, mode);
}

static int (*fcloseCallBack)(FILE *stream);

void Utils_FcloseCallBack(int (*cb)(FILE *stream)) {
  fcloseCallBack = cb;
}

int Utils_Fclose(FILE *stream) {
  if (fcloseCallBack) {
    return fcloseCallBack(stream);
  }
  return fclose(stream);
}

static int (*removeFileCallBack)(const char *fileName);

void Utils_RemoveFileCallBack(int (*cb)(const char *fileName)) {
  removeFileCallBack = cb;
}

int Utils_RemoveFile(const char *fileName) {
  if (removeFileCallBack) {
    return removeFileCallBack(fileName);
  }
  return remove(fileName);
}

MicroSecTimeStamp Utils_GetBeginningOfTime() {
  return 0; // it is 1/1/1970
}

bool Utils_Sleep(int16_t sec, MicroSecTimeStamp nanosec) {
  return HwAdapters_Sleep(sec, nanosec);
}

MicroSecTimeStamp Utils_GetFutureTimeuSec(SecTimeStamp addTimeSec) {
  struct timeval tval;

  gettimeofday(&tval, NULL);
  return (tval.tv_sec + addTimeSec) * (int64_t)1000000 + tval.tv_usec;
}

MicroSecTimeStamp Utils_GetTimeNowInuSec() {
  return Utils_GetFutureTimeuSec(0);
}

MicroSecTimeStamp Utils_GetFutureTimeSec(SecTimeStamp addTimeSec) {
  return Utils_GetFutureTimeuSec(addTimeSec) / 1000000;
}

MicroSecTimeStamp Utils_GetTimeNowInSec() {
  return Utils_GetFutureTimeSec(0);
}

void Utils_PrintHexStr(FILE *ofp, const char *header, const unsigned char *str, int16_t len) {
  int16_t i = 0;

  fprintf(ofp, "%s", header);
  if (str == NULL) return;
  for (i = 0; i < len; i++)
    fprintf(ofp, "%02x(%c)", str[i], str[i]);
  fprintf(ofp, "\n");
}

void Utils_PrintCharArray(FILE *ofp, const char *header, const unsigned char *str) {
  int16_t len = 0;

  if (str == NULL) {
    fprintf(ofp, "%s\n", header);
    return;
  }
  if (Utils_GetCharArrayLen(str, &len, 0, ERR_STR_LEN) == false) return;
  Utils_PrintHexStr(ofp, header, str, len + UTILS_STR_LEN_SIZE);
}

bool Utils_IsStringValid(const char *typeStr, const char *errStrPrefix, const char *str, int16_t minLen, int16_t maxLen) {
  int16_t i = 0, len = 0;

  if (str == NULL) {
    snprintf(errStr, sizeof(errStr), "%s, %s must not be NULL", typeStr, errStrPrefix);
    return false;
  }
  len = strlen(str);
  if (len < minLen || len > maxLen) {
    snprintf(errStr, sizeof(errStr), "%s, %s '%s' is not valid, its length must be in the range %d-%d", errStrPrefix, typeStr, str, minLen, maxLen);
    return false;
  }
  for (i = 0; i < len; i++) {
    if (isprint((int16_t)str[i]) == 0) {
      snprintf(errStr, sizeof(errStr), "%s, %s '%s' is not valid, it must "
                                       "contians onlt printable charachters",
               errStrPrefix, typeStr, str);
      return false;
    }
  }
  return true;
}

bool Utils_GenerateCharArray(const unsigned char *str, int16_t len, unsigned char **caStr) {
  unsigned char *ptr = NULL;

  if (str == NULL) return false;
  if (Utils_Malloc((void **)caStr, len + UTILS_STR_LEN_SIZE + 1) == false) return false;
  ptr = *caStr;
  memcpy(ptr + UTILS_STR_LEN_SIZE, str, len);
  if (Utils_SetCharArrayLen(*caStr, len) == false) return false;
  ptr[len + UTILS_STR_LEN_SIZE] = 0;
  return true;
}

bool Utils_ConvertCharArrayToStr(const unsigned char *caStr, unsigned char **str) {
  int16_t len = 0;

  if (caStr == NULL) return false;
  if (Utils_GetCharArrayLen(caStr, &len, 0, ERR_STR_LEN) == false) return false;
  return Utils_CreateAndCopyUcString(str, &(caStr[UTILS_STR_LEN_SIZE]), len);
}

bool Utils_GetCharArrayLen(const unsigned char *caStr, int16_t *len, int16_t minLen, int16_t maxLen) {
  int16_t i = 0;

  *len = 0;
  if (caStr == NULL) return false;
  for (i = 0; i < UTILS_STR_LEN_SIZE; i++) {
    if (caStr[i] == 0) return false;
    if (isdigit(caStr[i]) == false) {
      snprintf(errStr, sizeof(errStr), "Internal error: can't extract the string length from string, "
                                       "the %d leading bytes must digits\n",
               UTILS_STR_LEN_SIZE);
      return false;
    }
    *len = *len * 10 + caStr[i] - '0';
  }
  if (*len < minLen || *len > maxLen) {
    snprintf(errStr, sizeof(errStr), "string '%s' len %d is not in range %d-%d\n", caStr, *len, minLen, maxLen);
    return false;
  }
  return true;
}

bool Utils_SetCharArrayLen(unsigned char *caStr, int16_t len) {
  int16_t i = 0;

  if (caStr == NULL || len < 0) return false;
  for (i = UTILS_STR_LEN_SIZE - 1; i >= 0; i--) {
    caStr[i] = len % 10 + '0';
    len = len / 10;
  }
  return true;
}

// the str may not be NULL terminated
bool Utils_WriteCharArray(FILE *ofp, const unsigned char *caStr) {
  int16_t i = 0, len = 0;

  if (caStr == NULL || ofp == NULL) return false;
  if (Utils_GetCharArrayLen(caStr, &len, 0, ERR_STR_LEN) == false) return false;
  fprintf(ofp, "%03d", len);
  for (i = UTILS_STR_LEN_SIZE; i < len + UTILS_STR_LEN_SIZE; i++) {
    fprintf(ofp, "%02x", caStr[i]);
  }
  return true;
}

bool Utils_ReadCharArray(FILE *ifp, unsigned char *caStr, int16_t maxLen) {
  int16_t i = 0, len = 0;
  uint32_t data = 0;
  char strLen[10] = { 0 };
  unsigned char *ptr = NULL;

  if (caStr == NULL || ifp == NULL || maxLen < 0) return false;
  Utils_Fgets(strLen, UTILS_STR_LEN_SIZE+1, ifp); 
  len = atoi(strLen);
  if (len > maxLen - UTILS_STR_LEN_SIZE) {
    snprintf(errStr, sizeof(errStr), "Read new string from file is ilegal: length %d is too long > %d", len, maxLen - UTILS_STR_LEN_SIZE);
    return false;
  }
  ptr = caStr + UTILS_STR_LEN_SIZE;
  for (i = 0; i < len; i++) {
    if (Utils_Fgets(strLen, 3, ifp) == NULL) {
      snprintf(errStr, sizeof(errStr), "Read new string failed, read only %d out of %d bytes", i, len);
      return false;
    }
    sscanf(strLen, "%02x", (unsigned int *)&data); // for the mbed compiler
    ptr[i] = data;
  }
  Utils_SetCharArrayLen(caStr, len);
  caStr[len + UTILS_STR_LEN_SIZE] = 0;
  return true;
}

bool Utils_CharArrayCmp(const unsigned char *caStr1, const unsigned char *caStr2) {
  int16_t i = 0, len1 = 0, len2 = 0;

  if (caStr1 == NULL && caStr2 == NULL) return true;
  if (caStr1 == NULL || caStr2 == NULL) return false;
  if (Utils_GetCharArrayLen(caStr1, &len1, 0, ERR_STR_LEN) == false || Utils_GetCharArrayLen(caStr2, &len2, 0, ERR_STR_LEN) == false)
    return false;
  if (len1 != len2) {
    snprintf(errStr, sizeof(errStr), "Strings are not equal len1 %d != len2 %d", len1, len2);
    return false;
  }
  for (i = 0; i < len1 + UTILS_STR_LEN_SIZE; i++) {
    if (caStr1[i] != caStr2[i]) {
      snprintf(errStr, sizeof(errStr), "Strings are not equal at index %d %02x!=%02x", i, caStr1[i], caStr2[i]);
      return false;
    }
  }
  return true;
}

void Utils_PrintHash(const char *header, htab *t) {
  printf("%s", header);
  if (t == NULL) return;
  if (hfirst(t)) {
    do {
      printf("Key: '%s', val '%s'\n", (unsigned char *)hkey(t), (unsigned char *)hstuff(t));
    } while (hnext(t));
  }
}

void Utils_PrintHashKeys(const char *header, const char *prefix, htab *t) {
  printf("%s", header);
  if (t == NULL) return;
  if (hfirst(t)) {
    do {
      printf("%s'%s'\n", prefix, (unsigned char *)hkey(t));
    } while (hnext(t));
  }
}

bool Utils_AddToHash(htab *t, const unsigned char *key, int16_t keyLen, void *val) {
  unsigned char *keyStr = NULL;

  if (t == NULL || key == NULL || val == NULL) return false;
  if (hadd(t, key, keyLen, val)) {
    Utils_CreateAndCopyUcString(&keyStr, key, keyLen);
    hkey(t) = keyStr;
    hstuff(t) = val;
  } else {
    printf("Internal error: item: %s must be free\n", key);
    return false;
  }
  return true;
}

bool Utils_GetValFromHash(htab *t, const unsigned char *key, int16_t keyLen, void **val) {
  if (t == NULL || key == NULL || keyLen < 1) return false;
  if (hfind(t, key, keyLen) == false) {
    snprintf(errStr, sizeof(errStr), "Hash doesn't contain key '%s', len %d", key, keyLen);
    return false;
  }
  *val = (void *)hstuff(t);
  return true;
}

bool Utils_IsEqualHash(htab *t1, htab *t2) {
  char *key = NULL;

  if (t1 == NULL || t2 == NULL) return false;
  if (hcount(t1) != hcount(t2)) return false;
  if (hfirst(t1)) {
    do {
      key = (char *)hkey(t1);
      if (hfind(t2, (unsigned char *)key, strlen(key)) == false) return false;
    } while (hnext(t1));
  }
  return true;
}

bool Utils_DeleteKeyFromHash(htab *t, const unsigned char *key, int16_t keyLen) {
  if (t == NULL || key == NULL || keyLen < 1) return false;
  if (hfind(t, key, keyLen) == false) {
    return false;
  }
  Utils_Free(hkey(t));
  Utils_Free(hstuff(t));
  hdel(t);
  return true;
}

void Utils_FreeHash(htab *t) {
  if (t == NULL) return;
  while (hcount(t)) {
    Utils_Free(hkey(t));
    Utils_Free(hstuff(t));
    hdel(t);
  }
  hdestroy(t);
}

void Utils_FreeHashKeys(htab *t) {
  if (t == NULL) return;
  while (hcount(t)) {
    Utils_Free(hkey(t));
    hdel(t);
  }
  hdestroy(t);
}

void Utils_DuplicateHash(htab *origHash, htab *newHash) {
  if (newHash == NULL) return;
  if (origHash != NULL && hfirst(origHash)) {
    do {
      if (hadd(newHash, hkey(origHash), (ub4)strlen((char *)hkey(origHash)), hstuff(origHash))) {
        hkey(newHash) = hkey(origHash);
        hstuff(newHash) = hstuff(origHash);
      }
    } while (hnext(origHash));
  }
}

char *Utils_Fgets(char *str, int16_t maxLen, FILE *ifp) {
  return fgets(str, maxLen, ifp);
}

// Calculate a password's strength:
// The strength is calculated based on the password's length combined with the 
// diversity of letters, capital letters, digits and extra characters. Combining 
// the user name as part of the password weaken it by default.
// The effect of combining the user name (assuming it is 2 or more characters)
// changes depends on its case sensitivity:
// 1. If it is case senstive the password strength is limited by STRENGTH_SUFFICIENT
// 2. If it is case insenstive the password strength is limited by STRENGTH_POOR
// The results may be one of: 
///   STRENGTH_EXCELLENT - password contains at least 2 characters from each type 
//    STRENGTH_GOOD - password contains at least 2 characters from 3 of the 4 types 
//    STRENGTH_SUFFICIENT - password contains at least 2 characters from 2 of the 4 types
//                          or a case insensitive user name 
//    STRENGTH_POOR - password contains only characters from one of the 4 types
//                    or a case sensitive user name
PasswordStreangthType Utils_CalculatePasswordStrength(const unsigned char *sPwd, const unsigned char *userName) {
  int16_t i=0, len=0, maxStrength = STRENGTH_EXCELLENT, cntLen=0, pwdStrength=STRENGTH_NIL;
  int16_t cntVal[PWD_MAX_COUNTERS];
  char *tmpPwd=NULL, *tmpUser = NULL, *p = NULL;

  if (sPwd == NULL)
    return STRENGTH_POOR;
  len = strlen((const char *)sPwd);
  if (len < MIN_PASSWORD_LENGTH)
    return STRENGTH_POOR;
  cntLen = PWD_MAX_COUNTERS; // cntLen = sizeof(PwdCharType); doesn't work for MBED_OS
  if (cntLen > PWD_MAX_COUNTERS) {
      Utils_Abort("FATAL: Internal Error: too many password length counters\n");
  }
  for (i=0 ; i<PWD_MAX_COUNTERS ; i++)
    cntVal[i] = 0;
  // If the user name is 1 or 2 characters it is OK to have it in the password
  if (userName != NULL && strlen((const char *)userName) > 2) {
    Utils_CreateAndCopyString(&tmpPwd, (const char *)sPwd, len);
    Utils_CreateAndCopyString(&tmpUser, (const char *)userName, strlen((const char *)userName));
    p = tmpPwd;
    for ( ; *p; ++p) *p = tolower(*p);
    p = tmpUser;
    for ( ; *p; ++p) *p = tolower(*p);
    if (strstr((const char *)sPwd, (const char *)userName) != NULL) {
      maxStrength = STRENGTH_POOR;
    }
    else if (strstr(tmpPwd, tmpUser) != NULL) {
      maxStrength = STRENGTH_SUFFICIENT;
    }
    Utils_Free(tmpPwd);
    Utils_Free(tmpUser);
  }
  for (i=0 ; i<len ; i++) {
    if (isupper(sPwd[i])) {
      cntVal[UpperCaseIdx]++;
    }else if (islower(sPwd[i])) {
      cntVal[LowerCaseIdx]++;
    }else if (isdigit(sPwd[i])) {
      cntVal[DigitIdx]++;
    }else {
      cntVal[OtherIdx]++;
    }
  }
  for (i=0 ; i<cntLen ; i++) {
    if (cntVal[i] > 1)
      pwdStrength++;
  }  
  if (pwdStrength > maxStrength)
    pwdStrength = maxStrength;
  return pwdStrength;
}

// Generate a valid password that includes defaultPasswordLen characters with 2 Upper case characters, 2 numbers and 2 characters from
// "!@#$&-+;"
// The other method of select random byte array and verify if it fits the rules may take a lot of iterations to fit the rules
// The entropy is not perfect but its good enougth for one time reset password (map 0-255 to 97-122 total of 26)
bool Utils_GenerateNewValidPassword(unsigned char **sPwd, int16_t pwdLen) {
  int16_t i = 0, j = 0, idx = 0, shuffleIterations = 100, extraCharLen = strlen(EXTRA_CHARS), len = 0;
  unsigned char ch, pwdBuf[shuffleIterations];
  unsigned char *ptr = NULL;

  if (sPwd == NULL) return false;
  if (pwdLen < MIN_PASSWORD_LENGTH) {
    snprintf(errStr, sizeof(errStr), "Error: Password length %d, is ilegal, must be at least %d in "
                                     "order to have at least 2 chars, 2 digits and 2 extra charachters",
             pwdLen, MIN_PASSWORD_LENGTH);
    return false;
  }
  Utils_Malloc((void **)(sPwd), pwdLen + 1);
  ptr = *sPwd;
  Crypto_Random(ptr, pwdLen);
  // Entropy is not the best: random is 0-255 map to 0-21
  for (i = 0; i < pwdLen; i++) {
    if (ptr[i] < 'a' || ptr[i] > 'z') ptr[i] = (ptr[i] % ('z' - 'a')) + 'a';
  }

  // Replace 6 characters with 2 Upper case characters, 2 digits and 2 extra characters
  for (j = 0; j < 6 && j < pwdLen; j++) {
    if (j < 2) {
      ptr[j] = toupper(ptr[j]);
    } else if (j >= 2 && j < 4) {
      // entropy is not the best map 0-21 to 0-9
      ptr[j] = (ptr[j] % 10) + '0';
    } else {
      // entropy is not the best map 0-21 to 0-12
      ptr[j] = EXTRA_CHARS[ptr[j] % extraCharLen];
    }
  }

  // Shuffle the characters of the password except of the first one that must be a letter
  // The first char is always upper case
  len = sizeof(pwdBuf);
  Crypto_Random(pwdBuf, len);
  for (i = 0; i < len - 1; i++) {
    idx = (pwdBuf[i]) % (pwdLen - 2) + 1;
    ch = ptr[idx];
    ptr[idx] = ptr[idx + 1];
    ptr[idx + 1] = ch;
  }
  ptr[pwdLen] = 0;
  return true;
}
