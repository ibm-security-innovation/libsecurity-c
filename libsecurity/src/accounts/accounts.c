// Package accounts :
// The Account package handles user privileges and password management.
//
// The data structure is:
//  - Entity's privilege (Super user, Admin or User)
//  - Password related information and handling methods including:
//    - The current password
//    - The password's expiration time
//    - Old passwords that should be avoided. If there is an attempt to reused an old the user is flagged.
//    - Error counter: counts the number of consecutive unsuccessful authentication attempts
//    - Is it a 'temporary password' (after password reset)

#include "libsecurity/accounts/accounts_int.h"

bool Accounts_TestMode = false;
const char *usersPrivilegeStr[NUM_OF_PRIVILEGE] = { SUPER_USER_PERMISSION_STR, ADMIN_PERMISSION_STR, USER_PERMISSION_STR };

void Accounts_Print(FILE *ofp, const char *header, const void *u) {
  const AmUserInfoS *user = NULL;

  if (header != NULL) fprintf(ofp, "%s", header);
  if (u == NULL) return;
  user = (const AmUserInfoS *)u;
  fprintf(ofp, "Privilege: '%s'\n", usersPrivilegeStr[user->Privilege]);
  Pwd_Print(ofp, "", user->Pwd);
}

// The privilage must be from the valid options
STATIC bool checkPrivilegeValidity(const char *privilege, PrivilegeType *idx) {
  int16_t i = 0, len = 0;

  if (privilege == NULL) {
    assert(LIB_NAME "Privilege string must not be NULL" && (false || Accounts_TestMode));
    return false;
  }
  len = sizeof(usersPrivilegeStr) / sizeof(char *);
  for (i = 0; i < len; i++) {
    if (strcmp(privilege, usersPrivilegeStr[i]) == 0) {
      *idx = i;
      return true;
    }
  }
  snprintf(errStr, sizeof(errStr), "AccountManagement: The user privilege '%s' is not legal", privilege);
  *idx = USER_PERMISSION;
  return false;
}

bool Accounts_SetUserPrivilege(AmUserInfoS *user, const char *privilege) {
  PrivilegeType privilegeType = USER_PERMISSION;

  if (user == NULL || privilege == NULL) return false;
  if (checkPrivilegeValidity(privilege, &privilegeType) == false) return false;
  user->Privilege = privilegeType;
  return true;
}

STATIC MicroSecTimeStamp getPwdExpiration(AmUserInfoS *user, const char *userName) {
  if (user == NULL || userName == NULL) {
    assert(LIB_NAME "User structure and userName string must not be NULL" && (false || Accounts_TestMode));
    return Utils_GetBeginningOfTime();
  }
  if (strcmp(userName, ROOT_USER_NAME) == 0) { // root password dosn't have expiration limit
    return Utils_GetFutureTimeuSec(ROOT_PWD_EXPIRATION_DAYS * 24 * 3600);
  } else {
    return Utils_GetFutureTimeuSec(PWD_EXPIRATION_DAYS * 24 * 3600);
  }
}

// If the user is valid, add it (or override) to the list
bool Accounts_NewUser(AmUserInfoS **user, const char *privilege, const unsigned char *sPwd, const unsigned char *sSalt, PasswordStreangthType minPwdStrength) {
  PrivilegeType privilegeType = USER_PERMISSION;
  PwdS *p = NULL;

  if (sPwd == NULL || sSalt == NULL || privilege == NULL) {
    snprintf(errStr, sizeof(errStr), "Accounts_NewUser: pwd (isNull? %d), salt (isNull? %d) and "
                                     "privilege ('%s') must not be NULL",
             sPwd == NULL, sSalt == NULL, privilege);
    return false;
  }
  if (checkPrivilegeValidity(privilege, &privilegeType) == false) {
    return false;
  }
  if (Pwd_NewUserPwd(&p, sPwd, sSalt, minPwdStrength) == false) {
    Utils_AddPrefixToErrorStr("AccountManagement: AddNewUser failed, error: ");
    return false;
  }
  EntityManager_RegisterPropertyHandleFunc(AM_PROPERTY_NAME, Accounts_FreeUser, Accounts_Store, Accounts_Load, Accounts_Print, Accounts_IsEqual);
  Utils_Malloc((void **)(user), sizeof(AmUserInfoS));
  (*user)->Privilege = privilegeType;
  (*user)->Pwd = p;
  return true;
}

void Accounts_FreeUser(void *u) {
  AmUserInfoS *user = NULL;

  if (u == NULL) return;
  user = (AmUserInfoS *)u;
  Pwd_FreeUserPwd(user->Pwd);
  Utils_Free(user);
}

bool Accounts_UpdateUserPwd(AmUserInfoS *user, const char *userName, const unsigned char *cPwd, const unsigned char *newPwd, PasswordStreangthType minPwdStrength) {
  if (user == NULL || userName == NULL || cPwd == NULL || newPwd == NULL) return false;
  if (Pwd_UpdatePassword(user->Pwd, cPwd, newPwd, minPwdStrength) == false) return false;
  user->Pwd->Expiration = getPwdExpiration(user, userName);
  return true;
}

bool Accounts_VerifyPassword(AmUserInfoS *user, const unsigned char *sPwd) {
  if (user == NULL || sPwd == NULL) return false;
  if (Pwd_VerifyPassword(user->Pwd, sPwd) == false) {
    if (Accounts_TestMode == false) Utils_Sleep(0, 1000000L);
    user->Pwd->ErrorsCounter = 0; // the throttling is enougth
    return false;
  }
  return true;
}

STATIC bool amStructToStr(const AmUserInfoS *user, char *str, int16_t maxStrLen) {
  if (user == NULL || str == NULL) {
    assert(LIB_NAME "User structure and input string must not be NULL" && (false || Accounts_TestMode));
    return false;
  }
  snprintf(str, maxStrLen, AM_STRUCT_FMT, user->Privilege);
  return true;
}

// Store all users's account management info to the disk
bool Accounts_Store(const void *u, const SecureStorageS *storage, const char *prefix) {
  int16_t prefixLen = 0;
  bool ret = false;
  char str[MAX_AM_STR_LEN];
  char *key = NULL;
  const AmUserInfoS *user = NULL;

  if (u == NULL || storage == NULL) return false;
  if (Utils_IsPrefixValid("Accounts_Store", prefix) == false) return false;
  user = (const AmUserInfoS *)u;
  if (amStructToStr(user, str, MAX_AM_STR_LEN) == false) {
    snprintf(errStr, sizeof(errStr), "Accounts_Store: user parameter must not be NULL");
    return false;
  }
  prefixLen = strlen(prefix) + strlen(AM_PR_PREFIX) + 1;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, AM_PREFIX_FMT, AM_PR_PREFIX, prefix);
  debug_print("Accounts_Store write key '%s' val '%s'\n", key, str);
  ret = SecureStorage_AddItem(storage, (unsigned char *)key, strlen(key), (unsigned char *)str, strlen(str));
  Utils_Free(key);
  if (ret == false) {
    Utils_AddPrefixToErrorStr("Accounts_Store: Can't add item to storage, error");
    return false;
  }
  prefixLen = strlen(prefix) + strlen(AM_PWD_PREFIX) + 1;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, AM_PREFIX_FMT, AM_PWD_PREFIX, prefix);
  ret = Pwd_Store(user->Pwd, storage, key);
  Utils_Free(key);
  return ret;
}

bool Accounts_Load(void **u, const SecureStorageS *storage, const char *prefix, char **retName) {
  int16_t prefixLen = 0;
  PrivilegeType privilegeType = USER_PERMISSION;
  char *val = NULL, *key = NULL, *tName = NULL;
  PwdS *p = NULL;

  *retName = NULL;
  if (storage == NULL) {
    snprintf(errStr, sizeof(errStr), "Accounts_Load: Storage must initiated first");
    return false;
  }
  if (Utils_IsPrefixValid("Accounts_Load", prefix) == false) return false;
  prefixLen = strlen(prefix) + strlen(AM_PR_PREFIX) + 1;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, AM_PREFIX_FMT, AM_PR_PREFIX, prefix);
  if (SecureStorage_GetItem(storage, (unsigned char *)key, strlen(key), (unsigned char **)&val) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: Read from secure storage key '%s' not found", key);
    debug_print("Internal Error: Read from secure storage key '%s' not found\n", key);
    Utils_Free(key);
    return false;
  }
  debug_print("read: key: '%s' am info '%s'\n", key, val);
  privilegeType = atoi(val);
  Utils_Free(key);
  Utils_Free(val);
  debug_print("Load data for am: privilege %d '%s'\n", privilegeType, usersPrivilegeStr[privilegeType]);
  prefixLen = strlen(prefix) + strlen(AM_PWD_PREFIX) + 1;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, AM_PREFIX_FMT, AM_PWD_PREFIX, prefix);
  if (Pwd_Load((void **)&p, storage, key, &tName) == false) {
    Utils_Free(key);
    return false;
  }
  Utils_Free(key);
  Utils_Malloc((void **)(u), sizeof(AmUserInfoS));
  (*((AmUserInfoS **)u))->Privilege = privilegeType;
  (*((AmUserInfoS **)u))->Pwd = p;
  return true;
}

bool Accounts_IsEqual(const void *u1, const void *u2) {
  const AmUserInfoS *user1 = NULL, *user2 = NULL;

  if (u1 == NULL || u2 == NULL) return false;
  user1 = (const AmUserInfoS *)u1;
  user2 = (const AmUserInfoS *)u2;
  return (user1->Privilege == user2->Privilege && Pwd_IsEqual(user1->Pwd, user2->Pwd) == true);
}
