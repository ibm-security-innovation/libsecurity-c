// #include "test_password.h"

#include "libsecurity/password/password_int.h"

#define NUM_OF_USERS 4
#define MAX_USER_NAME_LENGTH 50

#define DEFAULT_PASSWORD ((unsigned char *)"a1b2c3d")
#define W_DEFAULT_PASSWORD ((unsigned char *)"a123db1234")
#define DEFAULT_SALT ((unsigned char *)"salt1234")
#define SECRET ((unsigned char *)"12345678901234567890123456789012")

STATIC bool testCheckValidPasswordLen() {
  int16_t i = 0, pwdLen = 0, len = MAX_PASSWORD_LENGTH + 2;
  bool pass = true, ret = false;
  char fmt[10];
  unsigned char caPwd[MAX_PASSWORD_LENGTH + 10 + UTILS_STR_LEN_SIZE];
  PwdS *p = NULL;

  if (Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT) == false) {
    printf("testCheckValidPasswordLen fail, can't generate userPwd, error: %s\n", errStr);
    return false;
  }
  sprintf(fmt, "%%0%dd", UTILS_STR_LEN_SIZE);
  sprintf((char *)caPwd, fmt, UTILS_STR_LEN_SIZE);
  for (i = 0; i < len; i++) {
    strcat((char *)caPwd, "a");
  }
  for (i = 0; i < len; i++) {
    Utils_SetCharArrayLen(caPwd, i);
    caPwd[i + UTILS_STR_LEN_SIZE] = 0;
    if (i > 0) caPwd[i - 1 + UTILS_STR_LEN_SIZE] = 'a';
    ret = Pwd_IsPwdValid(p, &(caPwd[UTILS_STR_LEN_SIZE]));
    Utils_GetCharArrayLen(caPwd, &pwdLen, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
    if (ret == false && pwdLen >= MIN_PASSWORD_LENGTH && pwdLen <= MAX_PASSWORD_LENGTH) {
      printf("testCheckValidPasswordLen fail: Legal password '%s', length %d was not "
             "accepted, error: %s\n",
             caPwd, pwdLen, errStr);
      pass = false;
      break;
    } else if (ret == true && (pwdLen < MIN_PASSWORD_LENGTH || pwdLen > MAX_PASSWORD_LENGTH)) {
      printf("testCheckValidPasswordLen fail: ilegal password length %d, '%s' was accepted\n", pwdLen, caPwd);
      pass = false;
      break;
    }
  }
  Pwd_FreeUserPwd(p);
  return pass;
}

// Fill the oldPasswords list with passwords and verify that
// random selected passwords are treated as expected
STATIC bool testCheckUnusabledOldPasswords() {
  int16_t i = 0, idx = 0, unused = 1;
  bool ret = false, pass = true;
  unsigned char sPwd[MAX_PASSWORD_LENGTH];
  unsigned char *cahPwd = NULL;
  char *fmt = "%s-%d";
  PwdS *p = NULL;

  if (Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT) == false) {
    printf("testCheckUnusabledOldPasswords fail, can't generate userPwd, error: %s\n", errStr);
    return false;
  }
  for (i = 0; i < DEFAULT_NUMBER_OF_OLD_PASSWORDS - unused; i++) {
    snprintf((char *)sPwd, sizeof(sPwd), fmt, DEFAULT_PASSWORD, i);
    generateSaltedHashPwd(sPwd, strlen((const char *)sPwd), DEFAULT_SALT, strlen((char *)DEFAULT_SALT), &cahPwd);
    p->OldHashedPasswords[i] = cahPwd;
  }
  for (i = 0; i < DEFAULT_NUMBER_OF_OLD_PASSWORDS * 2; i++) {
    idx = i % DEFAULT_NUMBER_OF_OLD_PASSWORDS;
    snprintf((char *)sPwd, sizeof(sPwd), fmt, DEFAULT_PASSWORD, idx);
    ret = Pwd_IsPwdValid(p, sPwd);
    if (ret == true && idx < DEFAULT_NUMBER_OF_OLD_PASSWORDS - unused) {
      printf("testCheckUnusabledOldPasswords fail: password '%s' was already "
             "used, but it was accepted\n",
             sPwd);
      Pwd_Print(stdout, "testCheckUnusabledOldPasswords\n", p);
      pass = false;
      break;
    } else if (ret == false && idx >= DEFAULT_NUMBER_OF_OLD_PASSWORDS - unused) {
      printf("testCheckUnusabledOldPasswords fail: password '%s' was rejected, "
             "but it was't used, "
             "error: %s\n",
             sPwd, errStr);
      Pwd_Print(stdout, "testCheckUnusabledOldPasswords\n", p);
      pass = false;
      break;
    }
  }
  Pwd_FreeUserPwd(p);
  return pass;
}

// Check if update password is respond as expected: for valid password it accept
// it
// and add it the previus password to the old passwords list
// and reject the previus password for the next defaultNumberOfOldPasswords
// passwords updates
STATIC bool testUpdatePwd1() {
  int16_t i = 0, j = 0, len = 0;
  bool pass = true;
  unsigned char cPwd[MAX_PASSWORD_LENGTH + 10];
  unsigned char pwd[MAX_PASSWORD_LENGTH + 10];
  char *pwdFmt = "%s-%03d";
  PwdS *p = NULL;

  Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT);
  memcpy(cPwd, DEFAULT_PASSWORD, strlen((char *)DEFAULT_PASSWORD) + 1);
  len = strlen((char *)DEFAULT_PASSWORD) + 4; // 4: pwdFmt: -%03d
  for (i = 0; i < DEFAULT_NUMBER_OF_OLD_PASSWORDS * 2; i++) {
    snprintf((char *)pwd, sizeof(pwd), pwdFmt, DEFAULT_PASSWORD, i);
    if (Pwd_UpdatePassword(p, cPwd, pwd) == false) {
      printf("testUpdateCharArrayPwd fail: idx %d, password '%s' rejected, but it was't used, error: %s\n", i, pwd, errStr);
      pass = false;
      break;
    }
    memcpy(cPwd, pwd, len + 1);
    for (j = i; j >= i - DEFAULT_NUMBER_OF_OLD_PASSWORDS && j >= 0; j--) {
      snprintf((char *)pwd, sizeof(pwd), pwdFmt, DEFAULT_PASSWORD, j);
      if (Pwd_UpdatePassword(p, cPwd, pwd) == true) {
        printf("testUpdateCharArrayPwd fail: password '%s' was already used, but it was accepted\n", pwd);
        pass = false;
        break;
      }
    }
  }
  Pwd_FreeUserPwd(p);
  return pass;
}

// Check that password could be updated only when the old password is used correctly
// In the odd indices, The curent password will point to the old password while
// in the even one it will point to the curent password
STATIC bool updatePwd(PwdS *p, bool isHashed) {
  int16_t i = 0, len = 0;
  bool pass = true, ret = false;
  char *cPwd = NULL, *pwdPtr = NULL,
       *pwdVec[] = { "0-This is real password", "1-aaa123", "2-123bbb", "3-1234ccc", "4-lalala this is the best", "5-aaa", "6- this is" };

  len = sizeof(pwdVec) / sizeof(char *);
  if (isHashed == false)
    cPwd = pwdPtr = (char *)DEFAULT_PASSWORD;
  else
    cPwd = pwdPtr = (char *)(p->hashPassword);
  for (i = 0; i < len; i++) {
    if (isHashed == false)
      ret = Pwd_UpdatePassword(p, (unsigned char *)cPwd, (unsigned char *)pwdVec[i]);
    else {
      ret = updatePassword(p, (unsigned char *)cPwd, (unsigned char *)pwdVec[i], true);
    }
    if (ret == true) pwdPtr = pwdVec[i];
    if ((i % 2 == 0 && ret == false) || (i % 2 == 1 && ret == true)) {
      printf("updatePwd fail: idx %d, curent password '%s' new password "
             "'%s' rejected, error: %s\n",
             i, pwdPtr, pwdVec[i], errStr);
      pass = false;
      break;
    }
    if (i % 2 == 1) {
      if (isHashed == false)
        cPwd = pwdPtr;
      else
        cPwd = (char *)(p->hashPassword);
    }
  }
  return pass;
}

// Check that password could be updated only when the old password is used correctly
// In the odd indices, The curent password will point to too old password while
// in the even one it will point to the curent password
STATIC bool testUpdatePwd() {
  int16_t i = 0;
  bool pass = true, isHash;
  PwdS *p = NULL;

  for (i = 0; i < 2; i++) {
    Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT);
    if (i == 0)
      isHash = false;
    else
      isHash = true;
    pass = pass && updatePwd(p, isHash);
    Pwd_FreeUserPwd(p);
  }
  return pass;
}

// Check that verify password works ok: it return true only if the following
// requiremnts are OK:
// The password is equal to the current password and the password is not expired
STATIC bool testVerifyPwd() {
  int16_t i = 0;
  bool pass = true, ret = false;
  PwdS *p = NULL;

  Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT);
  if (Pwd_VerifyPassword(p, DEFAULT_PASSWORD) == false) {
    printf("testVerifyPwd failed: password '%s' was not accepted but it is the "
           "same as the current password, error: %s\n",
           DEFAULT_PASSWORD, errStr);
    Pwd_FreeUserPwd(p);
    return false;
  }
  if (Pwd_VerifyPassword(p, W_DEFAULT_PASSWORD) == true) {
    printf("testVerifyPwd failed: password '%s' was approved but it is "
           "different from the current password\n",
           W_DEFAULT_PASSWORD);
    Pwd_FreeUserPwd(p);
    return false;
  }
  for (i = -2; i < 3; i++) {
    p->Expiration = (MicroSecTimeStamp) Utils_GetFutureTimeuSec(i);
    ret = Pwd_VerifyPassword(p, DEFAULT_PASSWORD);
    // i=0 is a race conditioon
    if (ret == true && i < 0) {
      printf("testVerifyPwd failed: password '%s' was approved but it is not valid (expired %" PRId64 ", time now %" PRId64 ")\n",
             DEFAULT_PASSWORD, (MicroSecTimeStamp)p->Expiration, (MicroSecTimeStamp)Utils_GetTimeNowInuSec());
      pass = false;
    } else if (ret == false && i > 0) {
      printf("testVerifyPwd failed: password '%s' was not approved but it is valid (expired %" PRId64 ", time now %" PRId64 "), error: %s\n",
             DEFAULT_PASSWORD, (MicroSecTimeStamp)p->Expiration, (MicroSecTimeStamp)Utils_GetTimeNowInuSec(), errStr);
    }
  }
  Pwd_FreeUserPwd(p);
  return pass;
}

// Check that one time password can be used exctly once
STATIC bool testUseOfTemporaryPwd() {
  bool pass = true;
  PwdS *p = NULL;

  Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT);
  Pwd_SetTemporaryPwd(p, true);
  if (Pwd_VerifyPassword(p, DEFAULT_PASSWORD) == false) {
    printf("testUseOfTemporaryPwd failed: password '%s' was not accepted but it is the same as the "
           "current password, current time %" PRId64 ", expiration time %" PRId64 ", error: %s\n",
           DEFAULT_PASSWORD, (MicroSecTimeStamp)Utils_GetTimeNowInuSec(), (MicroSecTimeStamp)p->Expiration, errStr);
    pass = false;
  }
  if (Pwd_VerifyPassword(p, DEFAULT_PASSWORD) == true) {
    printf("testUseOfTemporaryPwd failed: password '%s' was accepted but it was a one time password, "
           "and it was already used, current time %" PRId64 ", expiration time %" PRId64 " (diff %" PRId64 " uSec)\n",
           DEFAULT_PASSWORD, (MicroSecTimeStamp)Utils_GetTimeNowInuSec(), (MicroSecTimeStamp)p->Expiration, (MicroSecTimeStamp)((Utils_GetTimeNowInuSec() - p->Expiration)));
    pass = false;
  }
  Pwd_FreeUserPwd(p);
  return pass;
}

// Check that password is blocked after too many atempts
// and will be checked again only after new password setting
// Verify that successful attemt resets the attempts counter
STATIC bool testVerifyPwdBlocked() {
  int16_t i = 0, j = 0;
  bool pass = true, ret = false;
  unsigned char *newPwd = NULL, cPwd[MAX_PASSWORD_LENGTH + 1];
  PwdS *p = NULL;

  Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT);
  if (Pwd_VerifyPassword(p, DEFAULT_PASSWORD) == false) {
    printf("testVerifyPwdBlocked failed: password '%s' was not accepted but it is the same as the current password, error: %s\n",
           DEFAULT_PASSWORD, errStr);
    Pwd_FreeUserPwd(p);
    return false;
  }
  memcpy(cPwd, DEFAULT_PASSWORD, strlen((char *)DEFAULT_PASSWORD) + 1);
  for (i = 0; i < MAX_PWD_ATEMPTS * 2; i++) {
    for (j = 0; j < i; j++) {
      Pwd_VerifyPassword(p, W_DEFAULT_PASSWORD);
    }
    ret = Pwd_VerifyPassword(p, cPwd);
    if (ret == false && i <= MAX_PWD_ATEMPTS) {
      printf("testVerifyPwdBlocked failed: password was blocked after %d attempts, it should be blocked only after %d wrong attempts\n",
             i, MAX_PWD_ATEMPTS);
      pass = false;
    } else if (ret == true && i > MAX_PWD_ATEMPTS) {
      printf("testVerifyPwdBlocked failed: password was not blocked after %d wrong attempts, it should be blocked after %d wrong attempts\n",
             i, MAX_PWD_ATEMPTS);
      pass = false;
    } else if (ret == false && i >= MAX_PWD_ATEMPTS) {
      Utils_GenerateNewValidPassword((unsigned char **)(&newPwd), DEFAULT_PASSWORD_LEN);
      Pwd_UpdatePassword(p, cPwd, newPwd);
      memcpy(cPwd, newPwd, DEFAULT_PASSWORD_LEN + 1);
      if (Pwd_VerifyPassword(p, newPwd) == false) {
        printf("testVerifyPwdBlocked failed: password errorCoounter must be cleared after password set, counter attempts: %d, error %s\n",
               p->ErrorsCounter, errStr);
        pass = false;
      }
      Utils_Free(newPwd);
    }
    if (pass == false) break;
  }
  Pwd_FreeUserPwd(p);
  return pass;
}

// Verify that rundom passwords are generated corectly
STATIC bool testGenerateRandomPwd() {
  int16_t i = 0;
  bool pass = true;
  unsigned char *newPwd = NULL;
  unsigned char cPwd[MAX_PASSWORD_LENGTH + 1];
  PwdS *p = NULL;

  Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT);
  memcpy(cPwd, DEFAULT_PASSWORD, strlen((char *)DEFAULT_PASSWORD) + 1);
  for (i = 0; i < 1000; i++) {
    Utils_GenerateNewValidPassword((unsigned char **)(&newPwd), DEFAULT_PASSWORD_LEN);
    if (Pwd_UpdatePassword(p, cPwd, newPwd) == false) {
      printf("testGenerateRandomPwd failed: index %d, can't set password, error %s\n", i, errStr);
      printf("Try to set password %s, len %d:\n", newPwd, DEFAULT_PASSWORD_LEN);
      pass = false;
      break;
    }
    memcpy(cPwd, newPwd, DEFAULT_PASSWORD_LEN + 1);
    if (Pwd_VerifyPassword(p, cPwd) == false) {
      printf("testGenerateRandomPwd failed: password errorCoounter must be cleared after password set, counter attempts: %d, error %s\n",
             p->ErrorsCounter, errStr);
      pass = false;
      break;
    }
    Utils_Free(newPwd);
  }
  if (pass == false) {
    Utils_Free(newPwd);
  }
  Pwd_FreeUserPwd(p);
  return pass;
}

// Verify that stored password is equal to the loaded one
STATIC bool testStoreLoadPwd() {
  bool pass = true;
  char *prefix = "test-pwd";
  char *nameStr = NULL;
  PwdS *p1 = NULL, *p2 = NULL;
  SecureStorageS storage;

  Pwd_NewUserPwd(&p1, DEFAULT_PASSWORD, DEFAULT_SALT);
  updatePwd(p1, false);
  updatePassword(p1, DEFAULT_PASSWORD, W_DEFAULT_PASSWORD, false);
  Pwd_SetTemporaryPwd(p1, true);
  p1->Expiration = (MicroSecTimeStamp) Utils_GetFutureTimeuSec(100);
  p1->ErrorsCounter = MAX_PWD_ATEMPTS - 1;

  if (SecureStorage_NewStorage(SECRET, DEFAULT_SALT, &storage) == false) return false;
  if (Pwd_Store(p1, &storage, prefix) == false) {
    printf("testStoreLoadPwd failed: Error when try to store password to storage, error: %s\n", errStr);
    pass = false;
  }
  if (Pwd_Load((void **)(&p2), &storage, prefix, &nameStr) == false) {
    printf("testStoreLoadPwd failed: Error when try to load pwassword from storage, error: %s\n", errStr);
    pass = false;
  } else if (Pwd_IsEqual(p1, p2) == false) {
    printf("testStoreLoadPwd failed: User passwords are not equal\n");
    Pwd_Print(stdout, "p1:\n", p1);
    Pwd_Print(stdout, "p2:\n", p2);
    pass = false;
  }
#ifndef MBED_OS
  FILE *devNull = fopen("/dev/null", "w");
  Pwd_Print(devNull, "test print: ", (void *)p1);
  fclose(devNull);
#endif
  Pwd_FreeUserPwd(p1);
  Pwd_FreeUserPwd(p2);
  SecureStorage_FreeStorage(&storage);
  return pass;
}

STATIC bool testPwdCorners() {
  bool pass = true;
  PwdS *p = NULL;
  char *tmp;
  unsigned char *tmpP = NULL;

  if (Pwd_IsPwdValid(p, NULL) == true || Utils_GenerateNewValidPassword(NULL, 0) == true ||
      Utils_GenerateNewValidPassword(NULL, 0) == true || Pwd_Load(NULL, NULL, "A", &tmp) == true) {
    printf("testPwdCorners failed: Call to function with NULL returned true\n");
    pass = false;
  }
  Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT);
  Utils_Free(p->caSalt);
  Utils_CreateAndCopyString(&tmp, "1", 1);
  p->caSalt = (unsigned char *)tmp;
  if (isPwdValidHandler(p, DEFAULT_PASSWORD, false) == true || updatePasswordHandler(p, NULL, DEFAULT_PASSWORD, 1, true, false) == true) {
    printf("testPwdCorners failed: Call to function with wrong parameters returned true\n");
    pass = false;
  }
  Pwd_FreeUserPwd(p);
  Pwd_NewUserPwd(&p, DEFAULT_PASSWORD, DEFAULT_SALT);
  if (generateSaltedHashPwd(NULL, 8, DEFAULT_SALT, 10, &tmpP) == true || newUserPwdHandler(&p, NULL, 1, DEFAULT_SALT, 8, false) == true ||
      newUserPwdHandler(&p, DEFAULT_PASSWORD, 10, DEFAULT_SALT, 8, true) == true ||
      newUserPwdHandler(&p, p->hashPassword, 8, DEFAULT_SALT, 8, true) == true ||
      updatePasswordHandler(p, DEFAULT_PASSWORD, DEFAULT_SALT, 1, true, true) == true ||
      updatePasswordHandler(p, DEFAULT_SALT, DEFAULT_PASSWORD, 1, true, false) == true) {
    printf("testPwdCorners failed: Call to function with wrong parameters returned true\n");
    pass = false;
  }
  Pwd_FreeUserPwd(p);
  return pass;
}

#ifdef MBED_OS
int16_t testPassword()
#else
int main()
#endif
{
  bool pass = true;
  Pwd_TestMode = true;
  int16_t i = 0, len = 0;
  char *res = NULL;

  Pwd_TestMode = true;
  Utils_TestFuncS callFunc[] = { { "testCheckValidPasswordLen", testCheckValidPasswordLen },
                                 { "testCheckUnusabledOldPasswords", testCheckUnusabledOldPasswords },
                                 { "testVerifyPwd", testVerifyPwd },
                                 { "testUpdatePwd", testUpdatePwd },
                                 { "testUpdatePwd1", testUpdatePwd1 },
                                 { "testUseOfTemporaryPwd", testUseOfTemporaryPwd },
                                 { "testVerifyPwdBlocked", testVerifyPwdBlocked },
                                 { "testGenerateRandomPwd", testGenerateRandomPwd },
                                 { "testStoreLoadPwd", testStoreLoadPwd },
                                 { "testPwdCorners", testPwdCorners } };

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
