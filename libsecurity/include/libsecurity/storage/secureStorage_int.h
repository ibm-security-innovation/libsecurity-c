#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/storage/secureStorage.h"

#define TOTAL_STR_FMT "%03d"
#define TOTAL_AND_NUMBER_STR_LEN 4 // 03d +1 for string

#define KEY_VAL_MIN_STR_LEN 1
#define KEY_VAL_MAX_STR_LEN 512
#define MIN_SALT_LEN 0

#define DEF_SALT ((unsigned char *)"def-salt")
#define SIGN_LEN (SHA256_LEN + UTILS_STR_LEN_SIZE)
#define KEY_VAL_FMT "key: '%s' val: '%s',"
#define SECURE_STORAGE_FMT "Salt '%s'\nSign: '%s'\nData:"
#define STORAGE_TO_STR_FMT "Salt:'%s' secret:'%s', Data:"

#define MAX_ITEMS_IN_STORAGE 1000

#define READABLE_STORAGE true

#define SECURE_DEBUG 0
#define debug_print(fmt, ...)                                                                                                              \
  {                                                                                                                                        \
    if (SECURE_DEBUG) DEBUG(fmt, __VA_ARGS__);                                                                                             \
  }

extern bool Storage_TestMode;

STATIC void calcHashXor(unsigned char *dst, const unsigned char *in, int16_t len);
STATIC bool calcHash(const SecureStorageS *storage, unsigned char *hash);
STATIC bool getValue(htab *t, const unsigned char *key, unsigned char **val);
STATIC bool clearKey(const SecureStorageS *storage, const unsigned char *key);
STATIC void freeData(htab *t);
STATIC bool updateData(const SecureStorageS *storage, const unsigned char *key, const unsigned char *val);
STATIC bool isDataValid(const unsigned char *caSecret, const unsigned char *caSalt);
STATIC bool isSecretValid(const unsigned char *caSecret);
STATIC bool isSaltValid(const unsigned char *caSalt);
STATIC bool isLengthValid(const unsigned char *caStr, int16_t minLen, int16_t maxLen);
STATIC bool generateAlignedCharAray(const unsigned char *input, int16_t len, unsigned char *salt, int16_t saltLen, unsigned char **caOutput);
STATIC bool getRandomFromKey(const SecureStorageS *storage, const unsigned char *acKey, char unsigned *cahKey, unsigned char **carKey);
STATIC void generateRandomToKey(const unsigned char *key, unsigned char *hKey, unsigned char *rKey);
// STATIC int16_t readSecureFile(FILE *ifp, char *data, int16_t maxLen);
STATIC bool writeHeader(FILE *fp, SecureStorageS *storage);
STATIC bool readHeader(FILE *fp, SecureStorageS *storage);
STATIC void printDecryptedData(const char *header, unsigned char *caKey, unsigned char *caVal, const unsigned char *caSecret);
STATIC void writeKeyValue(FILE *fp, const SecureStorageS *storage);
STATIC bool readKeyValue(FILE *fp, const SecureStorageS *storage);
STATIC bool calcHMac(const SecureStorageS *storage, unsigned char *caData);
STATIC void getHKey(const unsigned char *caKey, unsigned char *cahKey);
STATIC bool encrypt(const unsigned char *caText, unsigned char *ivStr, const unsigned char *caSecret, unsigned char **caData);
STATIC bool decrypt(unsigned char *caText, const unsigned char *caSecret, unsigned char **caData);
// STATIC bool isEqual(const void *ts1, const void *ts2);
