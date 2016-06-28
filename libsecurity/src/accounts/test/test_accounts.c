#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/accounts/accounts_int.h"
#include "libsecurity/salt/salt_int.h"

#define NUM_OF_USERS 4
#define MAX_USER_NAME_LENGTH 50

#define DEFAULT_PASSWORD ((unsigned char *)"login-a1b2c3%$")
#define DEFAULT_SALT ((unsigned char *)"salt-a1b2c3d")
#define SECRET ((unsigned char *)"a!@#%^&*(()__+_)(}{|PPO?>O2:~`12")

// Test that only valid users can be generated
STATIC bool testNewUser() {
  int16_t j = 0, privelegeLen = 2, pwdLen = 0, saltLen = 0;
  bool ret = false, pass = true;
  char *privilege[] = { "aaa", USER_PERMISSION_STR };
  char pwd[MAX_PASSWORD_LENGTH * 10 + 1], salt[MAX_SALT_LEN * 10 + 1];
  AmUserInfoS *user;

  for (j = 0; j < privelegeLen; j++) {
    strcpy(pwd, "");
    for (pwdLen = 0; pwdLen < MAX_PASSWORD_LENGTH + 10; pwdLen += 4) {
      strcpy(salt, "");
      for (saltLen = 0; saltLen < MAX_SALT_LEN + 10; saltLen += 4) {
        ret = Accounts_NewUser(&user, privilege[j], (unsigned char *)pwd, (unsigned char *)salt, STRENGTH_SUFFICIENT);
        if (ret == true && (j == 0 || pwdLen < MIN_PASSWORD_LENGTH || pwdLen > MAX_PASSWORD_LENGTH || saltLen < MIN_SALT_LEN || saltLen > MAX_SALT_LEN)) {
          printf("testNewUser fail: AM was created but the parameters are not "
                 "legal: privilege '%s' pwdLen %d, saltLen %d\n", privilege[j], pwdLen, saltLen);
          pass = false;
        } else if (ret == false && (j > 0 && pwdLen >= MIN_PASSWORD_LENGTH && pwdLen <= MAX_PASSWORD_LENGTH && saltLen >= MIN_SALT_LEN &&
                                    saltLen <= MAX_SALT_LEN)) {
          printf("testNewUser fail: AM was not created but the parameters are legal: privilege "
                 "'%s' pwdLen %d, ('%s') saltLen %d ('%s'), error: %s\n", privilege[j], pwdLen, pwd, saltLen, salt, errStr);
          pass = false;
        }
        if (ret == true) {
          Accounts_FreeUser(user);
        }
        if (saltLen >= 0) strcat(salt, "ab12");
        if (pass == false) return false;
      }
      if (pwdLen >= 0) strcat(pwd, "#$ab");
    }
  }
  return pass;
}

STATIC bool testSetUserPrivilege() {
  int16_t i = 0, privelegeLen = 0;
  bool ret = false, pass = true;
  char *privilege[] = { "aaa", USER_PERMISSION_STR, SUPER_USER_PERMISSION_STR, ADMIN_PERMISSION_STR, "" };
  AmUserInfoS *user = NULL;

  privelegeLen = sizeof(privilege) / sizeof(char *);
  Accounts_NewUser(&user, SUPER_USER_PERMISSION_STR, DEFAULT_PASSWORD, (unsigned char *)"", STRENGTH_SUFFICIENT);
  for (i = 0; i < privelegeLen; i++) {
    ret = Accounts_SetUserPrivilege(user, privilege[i]);
    if (ret == true && (i == 0 || i == privelegeLen - 1)) {
      printf("testSetUserPrivilege fail: ilegal user privilege '%s' was setted\n", privilege[i]);
      pass = false;
    } else if (ret == false && i > 0 && i < privelegeLen - 1) {
      printf("testSetUserPrivilege fail: legal privilege was not setted '%s', index %d, error: %s\n", privilege[i], i, errStr);
      pass = false;
    }
  }
  Accounts_FreeUser(user);
  return pass;
}

// Check that password could be updated only when the old password is used
// correctly
// In the odd indices, The curent password will point to too old password while
// in the even one it will point to the curent password
STATIC bool testUpdateLoginPwd() {
  int16_t i = 0, len = 5;
  bool pass = true;
  bool ret = false;
  char *name = "user1", *pwdVec[5] = { "0-This is real password", "1-aaa123", "2-123bbb", "3-1234ccc", "4-lalala this is the best" };
  char *cPwd = NULL, *pwdPtr = NULL;
  AmUserInfoS *user = NULL;

  if (Accounts_NewUser(&user, SUPER_USER_PERMISSION_STR, DEFAULT_PASSWORD, (unsigned char *)"", STRENGTH_SUFFICIENT) == false) {
    printf("testUpdateLoginPwd: Failed to initilized user, error: %s\n", errStr);
    return false;
  }
  cPwd = (char *)DEFAULT_PASSWORD;
  for (i = 0; i < len; i++) {
    ret = Accounts_VerifyPassword(user, (unsigned char *)cPwd);
    if ((i % 2 == 0 && ret == false) || (i % 2 == 1 && ret == true)) {
      printf("testUpdateLoginPwd failed: in verify password, idx %d, curent "
             "password '%s' verify "
             "password '%s' match %d, expected match %d, error: %s\n",
             i, cPwd, pwdVec[i], ret, i % 2, errStr);
      pass = false;
    }
    ret = Accounts_UpdateUserPwd(user, name, (unsigned char *)cPwd, (unsigned char *)pwdVec[i], STRENGTH_SUFFICIENT);
    if (ret == true) pwdPtr = pwdVec[i];
    if ((i % 2 == 0 && ret == false) || (i % 2 == 1 && ret == true)) {
      printf("testUpdateLoginPwd failed: in update pwd idx %d, curent password "
             "'%s' new password "
             "'%s' reject %d, expect to reject %d, error: %s\n",
             i, cPwd, pwdVec[i], ret, i % 2, errStr);
      pass = false;
    }
    if (i % 2 == 1) cPwd = pwdPtr;
    if (pass == false) {
      break;
    }
  }
  Accounts_FreeUser(user);
  return pass;
}

// Verify that stored login is equal to the loaded one
STATIC bool testStoreLoadLogin() {
  bool pass = true;
  char *prefix = "test-login";
  char *tName = NULL;
  AmUserInfoS *u1 = NULL, *u2 = NULL;
  SecureStorageS storage;

  Accounts_NewUser(&u1, SUPER_USER_PERMISSION_STR, DEFAULT_PASSWORD, DEFAULT_SALT, STRENGTH_SUFFICIENT);
  if (SecureStorage_NewStorage(SECRET, DEFAULT_SALT, &storage) == false) {
    printf("testStoreLoadLogin failed: Error when try to create new storage, "
           "error: %s\n",
           errStr);
    return false;
  }
  if (Accounts_Store(u1, &storage, prefix) == false) {
    printf("testStoreLoadLogin failed: Error when try to store password to "
           "storage, error: %s\n",
           errStr);
    pass = false;
  }
  if (Accounts_Load((void **)(&u2), NULL, prefix, &tName) == true) {
    printf("testStoreLoadLogin failed: successfully load from NULL strorage\n");
    pass = false;
  }
  if (Accounts_Load((void **)(&u2), &storage, prefix, &tName) == false) {
    printf("testStoreLoadLogin failed: Error when try to load login from "
           "storage, error: %s\n",
           errStr);
    pass = false;
  } else if (Accounts_IsEqual(u1, u2) == false) {
    printf("testStoreLoadLogin failed: logins are not equal, error: %s\n", errStr);
    Accounts_Print(stdout, "User1:\n", u1);
    Accounts_Print(stdout, "User2:\n", u2);
    pass = false;
  }
  SecureStorage_FreeStorage(&storage);
  Accounts_FreeUser(u1);
  Accounts_FreeUser(u2);
  return pass;
}

STATIC bool testAccountsCorners() {
  int i, len = 3;
  double factor = 100000.0;
  bool pass = true;
  MicroSecTimeStamp val = 0;
  PrivilegeType privilegeType = USER_PERMISSION;
  AmUserInfoS *u1 = NULL;
  char *name[3] = { NULL, ROOT_USER_NAME, "A" };
  MicroSecTimeStamp expected[3] = { Utils_GetBeginningOfTime(), Utils_GetFutureTimeuSec(ROOT_PWD_EXPIRATION_DAYS * 24 * 3600) / factor,
                                    Utils_GetFutureTimeuSec(PWD_EXPIRATION_DAYS * 24 * 3600) / factor };

  Accounts_NewUser(&u1, SUPER_USER_PERMISSION_STR, DEFAULT_PASSWORD, DEFAULT_SALT, STRENGTH_SUFFICIENT);
  for (i = 0; i < len; i++) {
    if (i == 0)
      val = getPwdExpiration(NULL, name[i]);
    else
      val = getPwdExpiration(u1, name[i]) / factor;
    if (val != expected[i]) {
      printf("testAccountsCorners failed: getPwdExpiration user name '%s', expected value: %ld, return value %ld\n", name[i],
             (long)expected[i], (long)val);
      pass = false;
    }
  }
  if (checkPrivilegeValidity(NULL, &privilegeType) != false) {
    printf("testAccountsCorners failed: checkPrivilegeValidity expect to false\n");
    pass = false;
  }
#ifndef MBED_OS
  FILE *devNull = fopen("/dev/null", "w");
  Accounts_Print(devNull, "test print: ", (void *)u1);
  fclose(devNull);
#endif
  Accounts_FreeUser(u1);
  return pass;
}

#ifdef MBED_OS
int16_t testAccounts()
#else
int main()
#endif
{
  bool pass = true;
  Accounts_TestMode = true;
  int16_t i = 0, len = 0;
  char *res = NULL;

  Accounts_TestMode = true;
  Utils_TestFuncS callFunc[] = { { "testNewUser", testNewUser },
                                 { "testSetUserPrivilege", testSetUserPrivilege },
                                 { "testUpdateLoginPwd", testUpdateLoginPwd },
                                 { "testStoreLoadLogin", testStoreLoadLogin },
                                 { "testAccountsCorners", testAccountsCorners } };

  len = sizeof(callFunc) / sizeof(Utils_TestFuncS);

  for (i = 0; i < len; i++) {
    if ((callFunc[i]).testFunc() == false) {
      res = "fail";
      pass = false;
    } else
      res = "pass";
    printf("Test %s:'%s' %s\n", __FILE__, callFunc[i].name, res);
  }
  EntityManager_RemoveRegisteredPropertyList();
  return pass;
}
