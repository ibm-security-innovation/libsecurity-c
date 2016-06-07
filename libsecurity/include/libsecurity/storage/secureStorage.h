#pragma once

#include "libsecurity/libsecurity/libsecurity_params.h"
#include "libsecurity/utils/utils.h"
#include "libsecurity/utils/fileAdapters.h"

#include "hashtab/standard.h"
#include "hashtab/hashtab.h"

#ifdef MBED_OS

#ifdef __cplusplus
extern "C" {

#include "SDFileSystem.h"
}
#endif

#endif

#define SIGN_LEN (SHA256_LEN + UTILS_STR_LEN_SIZE)

typedef struct {
  unsigned char caSign[SIGN_LEN + 1]; // it represented as char array
  htab *Data;
  unsigned char *caSecret;
  unsigned char *caSalt;
} SecureStorageS;

bool SecureStorage_NewStorage(const unsigned char *sSecret, const unsigned char *sSalt, SecureStorageS *storage);
bool SecureStorage_AddItem(const SecureStorageS *storage, const unsigned char *sKey, int16_t keyLen, const unsigned char *sVal, int16_t valLen);
bool SecureStorage_GetItem(const SecureStorageS *storage, const unsigned char *skey, int16_t keyLen, unsigned char **sVal);
bool SecureStorage_RemoveItem(const SecureStorageS *storage, const unsigned char *sKey, int16_t keyLen);
bool SecureStorage_StoreSecureStorageToFile(const char *fileName, SecureStorageS *data);
bool SecureStorage_LoadSecureStorageFromFile(const char *fileName, const unsigned char *sSecret, const unsigned char *sSalt, SecureStorageS *storage);
void SecureStorage_FreeStorage(void *storage);
