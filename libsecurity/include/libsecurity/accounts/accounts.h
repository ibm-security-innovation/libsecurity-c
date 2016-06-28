#pragma once

#include "libsecurity/storage/secureStorage.h"
#include "libsecurity/utils/itemsList.h"

typedef struct {
  PwdS *Pwd;
  PrivilegeType Privilege;
} AmUserInfoS;

void Accounts_Print(FILE *ofp, const char *header, const void *user);
bool Accounts_NewUser(AmUserInfoS **user, const char *privilege, const unsigned char *sPwd, const unsigned char *sSalt, PasswordStreangthType minPwdStrength);
void Accounts_FreeUser(void *u);
bool Accounts_UpdateUserPwd(AmUserInfoS *user, const char *userName, const unsigned char *cPwd, const unsigned char *newPwd, PasswordStreangthType minPwdStrength);
bool Accounts_SetUserPrivilege(AmUserInfoS *user, const char *privilege);
bool Accounts_VerifyPassword(AmUserInfoS *user, const unsigned char *sPwd);
bool Accounts_Store(const void *u, const SecureStorageS *storage, const char *prefix);
bool Accounts_Load(void **u, const SecureStorageS *storage, const char *prefix, char **retName);
bool Accounts_IsEqual(const void *u1, const void *u2);
