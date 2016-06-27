#pragma once

#include "libsecurity/storage/secureStorage.h"
#include "libsecurity/entity/entityManager.h"
#include "libsecurity/salt/salt.h"

#define DEFAULT_NUMBER_OF_OLD_PASSWORDS 5

typedef struct {
  unsigned char *hashPassword;
  unsigned char *caSalt;
  MicroSecTimeStamp Expiration;
  int16_t ErrorsCounter;
  bool TemporaryPwd; // must be replaced after the first use
  unsigned char *OldHashedPasswords[DEFAULT_NUMBER_OF_OLD_PASSWORDS];
} PwdS;

void Pwd_Print(FILE *ofp, const char *header, const void *pwd);
bool Pwd_NewUserPwd(PwdS **newPwd, const unsigned char *sPwd, const unsigned char *sSalt, PasswordStreangthType minPwdStrength);
void Pwd_FreeUserPwd(void *pwd);
bool Pwd_GetHashedPwd(const unsigned char *caPwd, unsigned char hashPwd[crypto_hash_BYTES + UTILS_STR_LEN_SIZE + 1]);
bool Pwd_SetTemporaryPwd(PwdS *p, const bool flag);
bool Pwd_IsPwdValid(const PwdS *pwd, const unsigned char *sPwd);
bool Pwd_UpdatePassword(PwdS *pwd, const unsigned char *sPwd, const unsigned char *sNewPwd, PasswordStreangthType minPwdStrength);
bool Pwd_VerifyPassword(PwdS *pwd, const unsigned char *sPwd);
bool Pwd_Store(const void *pwd, const SecureStorageS *storage, const char *prefix);
bool Pwd_Load(void **loadPwd, const SecureStorageS *storage, const char *prefix, char **retName);
bool Pwd_IsEqual(const void *pwdS1, const void *pwdS2);
