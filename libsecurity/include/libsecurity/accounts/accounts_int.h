#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/utils/crypto.h"
#include "libsecurity/password/password.h"
#include "libsecurity/entity/entity.h"
#include "libsecurity/accounts/accounts.h"
#include "libsecurity/libsecurity/libsecurity_params.h"

extern bool Accounts_TestMode;

#define ROOT_PWD_EXPIRATION_DAYS 3550
#define PWD_EXPIRATION_DAYS 90

#define MAX_AM_STR_LEN 40
#define AM_PR_PREFIX "pr-"
#define AM_PWD_PREFIX "pw-"
#define AM_PREFIX_FMT "%s%s"
#define AM_STRUCT_FMT "%d\n"

#define AM_DEBUG 0
#define debug_print(fmt, ...)                                                                                                              \
  {                                                                                                                                        \
    if (AM_DEBUG) DEBUG(fmt, __VA_ARGS__);                                                                                                 \
  }

extern const char *usersPrivilege[NUM_OF_PRIVILEGE];

STATIC bool checkPrivilegeValidity(const char *privilege, PrivilegeType *privilegeType);
STATIC MicroSecTimeStamp getPwdExpiration(AmUserInfoS *user, const char *userName);
STATIC bool amStructToStr(const AmUserInfoS *user, char *str, int16_t maxStrLen);
