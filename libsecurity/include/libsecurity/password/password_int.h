#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "libsecurity/utils/utils.h"
#include "libsecurity/utils/crypto.h"
#include "libsecurity/password/password.h"

#define DEFAULT_PASSWORD_LEN 10
#define DEFAULT_EXPIRATION_DURATION_DAYS 90
#define DEFAULT_ONE_TIME_PASSWORD false
#define DEFAULT_PWD_ATEMPTS 10

#define MINIMAL_PWD_CHAR '!'

#define MAX_PWD_ATEMPTS DEFAULT_PWD_ATEMPTS

#define MAX_PWD_STR_LEN 128
#define PWD_PREFIX "w-"
#define PWD_PASS_PREFIX "p-"
#define PWD_SALT_PREFIX "s-"
#define PWD_OTHER_PREFIX "o-"
#define PWD_OLD_PWD_LEN_PREFIX "l-"
#define PWD_OLD_PWD_PREFIX "vp-"
#define PWD_PREFIX_FMT "%s%s%s"
#define PWD_OLD_P_LEN_PREFIX_FMT "%s%s"
#define PWD_OLD_P_PREFIX_FMT "%s-%d-%s"
#define PWD_STR_STRUCT_FMT "%s\n"
#define PWD_OTHER_STRUCT_PRINT_FMT "%d %d %" MY_PRId64 "\n"
#define PWD_OTHER_STRUCT_SCAN_FMT "%d %d %" MY_SCNd64 "\n"
#define PASS_STRUCT_IDX 0
#define SALT_STRUCT_IDX 1
#define OTHER_STRUCT_IDX 2
#define NUM_OF_STRUCTS 3

#define HASH_PWD_LEN (crypto_hash_BYTES + UTILS_STR_LEN_SIZE)

#define PWD_DEBUG 0
#define debug_print(fmt, ...)                                                                                                              \
  {                                                                                                                                        \
    if (PWD_DEBUG) DEBUG(fmt, __VA_ARGS__);                                                                                                \
  }

extern bool Pwd_TestMode;

STATIC bool newUserPwdHandler(PwdS **newPwd, const unsigned char *sPwd, int16_t pwdLen, const unsigned char *sSalt, int16_t saltLen, bool isPwdHashed);
STATIC bool isPwdLengthValid(const unsigned char *caPwd);
STATIC int16_t countOldHashedPassword();
STATIC bool isPwdValidHandler(const PwdS *pwd, const unsigned char *sPwd, bool isHashed);
STATIC bool generateSaltedHashPwd(const unsigned char *sPwd, int16_t pwdLen, const unsigned char *sSalt, int16_t saltLen, unsigned char **cahPwd);
STATIC MicroSecTimeStamp getNewDefaultPasswordExpirationTime(void);
STATIC bool updatePasswordHandler(PwdS *pwd, const unsigned char *sPwd, const unsigned char *sNewPwd, MicroSecTimeStamp expiration,
                                  bool oneTimePwd, bool isHashedPwd);

#ifdef STATIC_F
STATIC bool updatePassword(PwdS *pwd, const unsigned char *sPwd, const unsigned char *sNewPwd, bool isHashedPwd);
#endif
STATIC void structToStr(const PwdS *pwd, int16_t idx, char **str, int16_t *len);
STATIC bool storeOldPasswords(const PwdS *pwd, const SecureStorageS *storage, const char *prefix);
STATIC bool loadOldPasswords(PwdS *pwd, const SecureStorageS *storage, const char *prefix);
