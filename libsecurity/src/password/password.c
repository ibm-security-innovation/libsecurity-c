// Package password : The password package provides implementation of Password services: Encryption, salting, reset, time expiration and
// throttling.
//
// The password package handles the following:
//  - Generating a new (salted) password,
//  - Checking if a given password matches a given user's password
//  - Updating a user's password
//  - Resetting a password to a password that can only be used once within a predifined window of time
//
// Passwords have the following properties:
//  - The current password
//  - The password's expiration time
//  - Old passwords that should be avoided. If there is an attempt to reused an old the user is flagged.
//  - Error counter: counts the number of consecutive unsuccessful authentication attempts
//  - Is it a 'temporary password' (after password reset)
//
// Note that users are also flagged if they attempt to use a one-time-passwords more than once

#include "libsecurity/password/password_int.h"

bool Pwd_TestMode = false;

void Pwd_Print(FILE *ofp, const char *header, const void *pwd) {
  int16_t cnt = 0;
  const PwdS *p = NULL;

  if (header != NULL) fprintf(ofp, "%s", header);
  if (pwd == NULL) {
    snprintf(errStr, sizeof(errStr), "Pwd struct must not be NULL");
    return;
  }
  p = (const PwdS *)pwd;
  cnt = countOldHashedPassword(p);
  fprintf(ofp, "User password: Expiration: %" MY_PRId64 ", Errors counter: %d, One time password: %d, Number of old passwords: %d\n",
    (int32_t)(p->Expiration >> 32), (int32_t)(p->Expiration), p->ErrorsCounter, p->TemporaryPwd, cnt);
}

STATIC bool isPwdLengthValid(const unsigned char *caPwd) {
  int16_t len = 0;

  if (caPwd != NULL) Utils_GetCharArrayLen(caPwd, &len, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
  if (caPwd == NULL || len == 0 || len < MIN_PASSWORD_LENGTH || len > MAX_PASSWORD_LENGTH) {
    snprintf(errStr, sizeof(errStr), "Password is not valid, its length %d must be between %d-%d", len, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
    return false;
  }
  return true;
}

// The password should be handled and stored as hashed and not in clear text
bool Pwd_GetHashedPwd(const unsigned char *caPwd, unsigned char hashPwd[HASH_PWD_LEN + 1]) {
  int16_t len = 0;
  unsigned char *orgPwd = NULL;

  if (caPwd == NULL || hashPwd == NULL) return false;
  memset(hashPwd, 0, HASH_PWD_LEN);
  Utils_GetCharArrayLen(caPwd, &len, 1, MAX_PWD_STR_LEN);
  Utils_ConvertCharArrayToStr(caPwd, &orgPwd);
  Crypto_SHA256(orgPwd, len, (unsigned char *)hashPwd);
  Utils_Free(orgPwd);
  if (Utils_SetCharArrayLen(hashPwd, crypto_hash_BYTES) == false) return false;
  return true;
}

// Verify that the password is legal: its length is OK and it wasn't recently used
STATIC bool isPwdValidHandler(const PwdS *pwd, const unsigned char *sPwd, bool isHashed) {
  int16_t i, saltLen = 0, len = 0;
  unsigned char *cahPwd = NULL;

  if (pwd == NULL || sPwd == NULL) {
    snprintf(errStr, sizeof(errStr), "Password structure and new password must not be null");
    assert(LIB_NAME "Password structure and new password must not be NULL" && (false || Pwd_TestMode));
    return false;
  }
  if (Utils_GetCharArrayLen(pwd->caSalt, &saltLen, MIN_SALT_LEN, MAX_SALT_LEN) == false) {
    snprintf(errStr, sizeof(errStr), "Pwd_IsPwdValid: The given salt is not legal");
    return false;
  }
  if (isHashed) {
    if (Utils_GetCharArrayLen(sPwd, &len, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == false) return false;
    Utils_CreateAndCopyUcString(&cahPwd, sPwd, len + UTILS_STR_LEN_SIZE);
  } else {
    len = strlen((const char *)sPwd);
    if (generateSaltedHashPwd(sPwd, len, &(pwd->caSalt[UTILS_STR_LEN_SIZE]), saltLen, &cahPwd) == false) {
      return false;
    }
  }
  for (i = 0; i < DEFAULT_NUMBER_OF_OLD_PASSWORDS; i++) {
    if (pwd->OldHashedPasswords[i] != NULL && Utils_CharArrayCmp(cahPwd, pwd->OldHashedPasswords[i]) == true) {
      snprintf(errStr, sizeof(errStr), "The new password is illegal: it was "
                                       "already used, please select a new password");
      Utils_Free(cahPwd);
      return false;
    }
  }
  Utils_Free(cahPwd);
  return true;
}

// Verify that the password is legal: its length is OK and it wasn't recently used
bool Pwd_IsPwdValid(const PwdS *pwd, const unsigned char *sPwd) {
  if (pwd == NULL || sPwd == NULL) {
    snprintf(errStr, sizeof(errStr), "Password structure and new password must not be null");
    return false;
  }
  return isPwdValidHandler(pwd, sPwd, false);
}

STATIC MicroSecTimeStamp getNewDefaultPasswordExpirationTime() {
  return Utils_GetFutureTimeuSec(DEFAULT_EXPIRATION_DURATION_DAYS * 24 * 3600);
}

STATIC bool generateSaltedHashPwd(const unsigned char *sPwd, int16_t pwdLen, const unsigned char *sSalt, int16_t saltLen, unsigned char **cahPwd) {
  unsigned char *caPwd = NULL, *genPwd = NULL, *caSalt = NULL;

  if (sPwd == NULL || sSalt == NULL || pwdLen < 0 || saltLen < 0) {
    snprintf(errStr, sizeof(errStr), "generateSaltedHashPwd: password ('%s'), "
                                     "pwd len %d, salt ('%s', salt len %d must "
                                     "be legal",
             sPwd, pwdLen, sSalt, saltLen);
    assert(LIB_NAME "Password (and pwd length), salt (and salt lebgth) must be valid" && (false || Pwd_TestMode));
    return false;
  }
  if (Utils_GenerateCharArray(sPwd, pwdLen, &caPwd) == false) {
    return false;
  }
  if (isPwdLengthValid(caPwd) == false) {
    Utils_Free(caPwd);
    return false;
  }
  if (Utils_GenerateCharArray(sSalt, saltLen, &caSalt) == false) {
    Utils_Free(caPwd);
    return false;
  }
  if (Salt_GenerateCharArraySaltedPassword(caPwd, caSalt, &genPwd) == false) {
    Utils_Free(caPwd);
    Utils_Free(caSalt);
    return false;
  }
  Utils_Free(caPwd);
  Utils_Free(caSalt);
  Utils_Malloc((void **)cahPwd, HASH_PWD_LEN + 1);
  Pwd_GetHashedPwd(genPwd, *cahPwd);
  Utils_Free(genPwd);
  return true;
}

STATIC bool newUserPwdHandler(PwdS **newPwd, const unsigned char *sPwd, int16_t pwdLen, const unsigned char *sSalt, int16_t saltLen, bool isPwdHashed) {
  int16_t i = 0, len = 0, sLen = 0;
  unsigned char *cahPwd = NULL, *caSalt = NULL;

  if (sPwd == NULL || sSalt == NULL || pwdLen < 0 || saltLen < 0) {
    snprintf(errStr, sizeof(errStr), "newUserPwdHandler: password ('%s'), pwd len %d, salt ('%s'), salt len %d must be legal", sPwd, pwdLen,
             sSalt, saltLen);
    assert(LIB_NAME "Password (and pwd length), salt (and salt lebgth) must be valid" && (false || Pwd_TestMode));
    return false;
  }
  if (isPwdHashed) {
    if (Utils_GetCharArrayLen(sPwd, &len, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == false) {
      snprintf(errStr, sizeof(errStr), "newUserPwdHandler: The given hashed password is not legal");
      return false;
    }
    Utils_CreateAndCopyUcString(&cahPwd, sPwd, len + UTILS_STR_LEN_SIZE);
    if (Utils_GetCharArrayLen(sSalt, &sLen, MIN_SALT_LEN, MAX_SALT_LEN) == false) {
      snprintf(errStr, sizeof(errStr), "newUserPwdHandler: The given salt is not legal");
      Utils_Free(cahPwd);
      return false;
    }
    Utils_CreateAndCopyUcString(&caSalt, sSalt, sLen + UTILS_STR_LEN_SIZE);
  } else {
    if (Utils_GenerateCharArray(sSalt, saltLen, &caSalt) == false) {
      return false;
    }
    if (generateSaltedHashPwd(sPwd, pwdLen, sSalt, saltLen, &cahPwd) == false) {
      Utils_Free(caSalt);
      return false;
    }
  }
  EntityManager_RegisterPropertyHandleFunc(PWD_PROPERTY_NAME, Pwd_FreeUserPwd, Pwd_Store, Pwd_Load, Pwd_Print, Pwd_IsEqual);
  Utils_Malloc((void **)(newPwd), sizeof(PwdS));
  (*newPwd)->hashPassword = cahPwd;
  (*newPwd)->caSalt = caSalt;
  (*newPwd)->Expiration = getNewDefaultPasswordExpirationTime();
  (*newPwd)->ErrorsCounter = 0;
  (*newPwd)->TemporaryPwd = DEFAULT_ONE_TIME_PASSWORD; // must be replaced after the first use
  for (i = 0; i < DEFAULT_NUMBER_OF_OLD_PASSWORDS; i++)
    (*newPwd)->OldHashedPasswords[i] = NULL;
  return true;
}

// Generate a new userPwd for a given userId and password
// The generated password is with a default expiration time
bool Pwd_NewUserPwd(PwdS **newPwd, const unsigned char *sPwd, const unsigned char *sSalt) {
  if (sPwd == NULL || sSalt == NULL || newPwd == NULL) {
    snprintf(errStr, sizeof(errStr), "Pwd_NewUserPwd: Password and salt strings must not be NULL");
    return false;
  }
  return newUserPwdHandler(newPwd, sPwd, (int16_t)strlen((const char *)sPwd), sSalt, (int16_t)strlen((const char *)sSalt), false);
}

void Pwd_FreeUserPwd(void *pwd) {
  PwdS *p = NULL;
  int16_t i = 0;

  if (pwd == NULL) return;
  p = (PwdS *)pwd;
  Utils_Free(p->hashPassword);
  Utils_Free(p->caSalt);
  for (i = 0; i < DEFAULT_NUMBER_OF_OLD_PASSWORDS; i++) {
    Utils_Free(p->OldHashedPasswords[i]);
  }
  Utils_Free(p);
}

bool Pwd_SetTemporaryPwd(PwdS *p, const bool flag) {
  if (p == NULL) return false;
  p->TemporaryPwd = flag;
  return true;
}

// Update the password, it's expioration time and it's state (is it a one-time-password or a regular one)
STATIC bool updatePasswordHandler(PwdS *pwd, const unsigned char *sPwd, const unsigned char *sNewPwd, MicroSecTimeStamp expiration,
                                  bool temporaryPwd, bool isHashedPwd) {
  int16_t i = 0, len = 0, saltLen = 0;
  unsigned char *cahPwd = NULL, *cahPwd1 = NULL;

  if (pwd == NULL || sPwd == NULL || sNewPwd == NULL) return false;
  if (Utils_GetCharArrayLen(pwd->caSalt, &saltLen, MIN_SALT_LEN, MAX_SALT_LEN) == false) {
    snprintf(errStr, sizeof(errStr), "updatePasswordHandler: The given salt is not legal");
    return false;
  }
  if (isPwdValidHandler(pwd, sPwd, isHashedPwd) == false || Pwd_IsPwdValid(pwd, sNewPwd) == false) {
    return false;
  }
  if (isHashedPwd) {
    if (Utils_GetCharArrayLen(sPwd, &len, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == false) {
      snprintf(errStr, sizeof(errStr), "updatePasswordHandler: The given hashed password is not legal");
      return false;
    }
    Utils_CreateAndCopyUcString(&cahPwd, sPwd, len + UTILS_STR_LEN_SIZE);
  } else {
    if (generateSaltedHashPwd(sPwd, strlen((const char *)sPwd), &(pwd->caSalt[UTILS_STR_LEN_SIZE]), saltLen, &cahPwd) == false) {
      snprintf(errStr, sizeof(errStr), "problem was found while verifing the new password");
      return false;
    }
  }
  if (Utils_CharArrayCmp(cahPwd, pwd->hashPassword) == false) {
    snprintf(errStr, sizeof(errStr), "Can't update new password, The given "
                                     "password dosn't match the curent password");
    Utils_Free(cahPwd);
    return false;
  }
  Utils_Free(cahPwd);
  if (generateSaltedHashPwd(sNewPwd, strlen((const char *)sNewPwd), &(pwd->caSalt[UTILS_STR_LEN_SIZE]), saltLen, &cahPwd1) == false) {
    snprintf(errStr, sizeof(errStr), "problem was found while verifing the new password");
    return false;
  }
  if (Utils_CharArrayCmp(cahPwd1, pwd->hashPassword) == true) {
    snprintf(errStr, sizeof(errStr), "The new password is illegal: it is "
                                     "currently in use, please select a new password");
    Utils_Free(cahPwd1);
    return false;
  }
  Utils_Free(pwd->OldHashedPasswords[DEFAULT_NUMBER_OF_OLD_PASSWORDS - 1]);
  for (i = DEFAULT_NUMBER_OF_OLD_PASSWORDS - 1; i > 0; i--) {
    pwd->OldHashedPasswords[i] = pwd->OldHashedPasswords[i - 1];
  }
  pwd->OldHashedPasswords[0] = pwd->hashPassword;
  pwd->hashPassword = cahPwd1;
  pwd->Expiration = expiration;
  pwd->ErrorsCounter = 0;
  pwd->TemporaryPwd = temporaryPwd;
  return true;
}

#ifdef STATIC_F
STATIC bool updatePassword(PwdS *pwd, const unsigned char *sPwd, const unsigned char *sNewPwd, bool isHashedPwd) {
  return updatePasswordHandler(pwd, sPwd, sNewPwd, getNewDefaultPasswordExpirationTime(), DEFAULT_ONE_TIME_PASSWORD, isHashedPwd);
}
#endif

// Update password and expiration time
bool Pwd_UpdatePassword(PwdS *pwd, const unsigned char *sPwd, const unsigned char *sNewPwd) {
  if (pwd == NULL || sPwd == NULL || sNewPwd == NULL) return false;
  return updatePasswordHandler(pwd, sPwd, sNewPwd, getNewDefaultPasswordExpirationTime(), DEFAULT_ONE_TIME_PASSWORD, false);
}

// Verify that the given password is the expected one and that it is not expired
bool Pwd_VerifyPassword(PwdS *pwd, const unsigned char *sPwd) {
  int16_t saltLen = 0;
  unsigned char *cahPwd = NULL;

  if (pwd == NULL || sPwd == NULL) return false;
  if (pwd->ErrorsCounter > DEFAULT_PWD_ATEMPTS) {
    snprintf(errStr, sizeof(errStr), "Too many passwords attempts, Reset password before the next try");
    return false;
  }
  if (Pwd_IsPwdValid(pwd, sPwd) == false) return false;
  if (Utils_GetCharArrayLen(pwd->caSalt, &saltLen, MIN_SALT_LEN, MAX_SALT_LEN) == false) return false;
  if (generateSaltedHashPwd(sPwd, strlen((const char *)sPwd), &(pwd->caSalt[UTILS_STR_LEN_SIZE]), saltLen, &cahPwd) == false) return false;
  if (Utils_CharArrayCmp(cahPwd, pwd->hashPassword) == false) {
    Utils_Free(cahPwd);
    pwd->ErrorsCounter++;
    snprintf(errStr, sizeof(errStr), "Password is wrong, please try again");
    return false;
  }
  Utils_Free(cahPwd);
  // If the password expired
  if (Utils_GetTimeNowInuSec() > pwd->Expiration) {
    int64_t tmp = (Utils_GetTimeNowInuSec() - pwd->Expiration) / 1000000;
    snprintf(errStr, sizeof(errStr), "Password has expired (%" MY_PRId64 " Sec), please replace it.", (int32_t)(tmp >> 32), (int32_t) tmp);
    return false;
  }
  if (pwd->TemporaryPwd == true) {
    pwd->Expiration = Utils_GetFutureTimeuSec(-1000);
    pwd->TemporaryPwd = DEFAULT_ONE_TIME_PASSWORD; // Reset to the default option
    // for the next password
  }
  pwd->ErrorsCounter = 0;
  return true;
}

// Convert the Otp structure into string to be saved/printited later
STATIC void structToStr(const PwdS *pwd, int16_t idx, char **str, int16_t *len) {
  int16_t tmpLen = 0;
  unsigned char *ptr = NULL;

  if (pwd == NULL) {
    assert(LIB_NAME "Password structure must not be NULL" && (false || Pwd_TestMode));
    return;
  }
  *len = 0;
  switch (idx) {
    case PASS_STRUCT_IDX:
      Utils_GetCharArrayLen(pwd->hashPassword, &tmpLen, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
      *len += tmpLen + UTILS_STR_LEN_SIZE;
      ptr = pwd->hashPassword;
      break;
    case SALT_STRUCT_IDX:
      Utils_GetCharArrayLen(pwd->caSalt, &tmpLen, MIN_SALT_LEN, MAX_SALT_LEN);
      *len += tmpLen + UTILS_STR_LEN_SIZE;
      ptr = pwd->caSalt;
      break;
    case OTHER_STRUCT_IDX:
      *len += 3 + sizeof(pwd->Expiration) * 2 + sizeof(pwd->ErrorsCounter) + sizeof(pwd->TemporaryPwd);
      // 3 is for the spaces between the numbers, *2 is for %lx
      break;
    default:
      Utils_Abort("Internal error unknown case in Pwd.c, structToStr");
  }
  Utils_Malloc((void **)(str), *len + 1);
  if (idx == OTHER_STRUCT_IDX) {
    snprintf(*str, *len + 1, PWD_OTHER_STRUCT_PRINT_FMT, pwd->ErrorsCounter, pwd->TemporaryPwd, (int32_t)(pwd->Expiration>>32), (int32_t)pwd->Expiration);
  } else {
    memcpy(*str, ptr, *len + 1);
  }
}

STATIC int16_t countOldHashedPassword(const PwdS *pwd) {
  int16_t i = 0, len = 0;

  if (pwd == NULL) {
    assert(LIB_NAME "Password structure must not be NULL" && (false || Pwd_TestMode));
    return 0;
  }
  for (i = 0; i < DEFAULT_NUMBER_OF_OLD_PASSWORDS && pwd->OldHashedPasswords[i] != NULL; i++) {
    len = i + 1;
  }
  return len;
}

STATIC bool storeOldPasswords(const PwdS *pwd, const SecureStorageS *storage, const char *prefix) {
  int16_t i = 0, len = 0, prefixLen = 0, pwdLen = 0;
  char *key = NULL, val[10];

  if (pwd == NULL || storage == NULL) {
    assert(LIB_NAME "Password structure and storage structure must not be NULL" && (false || Pwd_TestMode));
    return false;
  }
  if (Utils_IsPrefixValid("Pwd:storeOldPasswords", prefix) == false) return false;
  len = countOldHashedPassword(pwd);
  prefixLen = strlen(prefix) + strlen(PWD_OLD_PWD_LEN_PREFIX) + 1;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, PWD_OLD_P_LEN_PREFIX_FMT, PWD_OLD_PWD_LEN_PREFIX, prefix);
  snprintf(val, sizeof(val), "%d\n", len);
  debug_print("Pwd_Store write old passwords key '%s', val %s", key, val);
  if (SecureStorage_AddItem(storage, (unsigned char *)key, strlen(key), (unsigned char *)val, strlen(val)) == false) {
    Utils_AddPrefixToErrorStr("Can't add item to storage, error");
    Utils_Free(key);
    return false;
  }
  Utils_Free(key);
  prefixLen = strlen(prefix) + strlen(PWD_OLD_PWD_PREFIX) + 5; // 5 is for the integer length and for the string
  Utils_Malloc((void **)(&key), prefixLen);
  for (i = 0; i < len; i++) {
    if (Utils_GetCharArrayLen(pwd->OldHashedPasswords[i], &pwdLen, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == false) {
      Utils_Free(key);
      return false;
    }
    snprintf(key, prefixLen, PWD_OLD_P_PREFIX_FMT, PWD_OLD_PWD_PREFIX, i, prefix);
    if (PWD_DEBUG) {
      debug_print("Pwd_Store write old passwords key '%s', ", key);
      Utils_PrintCharArray(stderr, " val: ", pwd->OldHashedPasswords[i]);
      debug_print("%s", "\n");
    }
    if (SecureStorage_AddItem(storage, (unsigned char *)key, strlen(key), pwd->OldHashedPasswords[i], pwdLen + UTILS_STR_LEN_SIZE) == false) {
      Utils_AddPrefixToErrorStr("Can't add item to storage, error");
      Utils_Free(key);
      return false;
    }
  }
  Utils_Free(key);
  return true;
}

bool Pwd_Store(const void *pwd, const SecureStorageS *storage, const char *prefix) {
  int16_t i = 0, strLen = 0, prefixLen = 0;
  char *pwdStr = NULL, *key = NULL, *err = NULL;
  const char *prefixStrVec[NUM_OF_STRUCTS] = { PWD_PASS_PREFIX, PWD_SALT_PREFIX, PWD_OTHER_PREFIX };
  const PwdS *p = NULL;

  if (pwd == NULL || storage == NULL) return false;
  if (Utils_IsPrefixValid("Pwd_Store", prefix) == false) return false;
  p = (const PwdS *)pwd;
  for (i = 0; i < NUM_OF_STRUCTS; i++) {
    structToStr(p, i, &pwdStr, &strLen);
    prefixLen = strlen(prefix) + strlen(PWD_PREFIX) + strlen(prefixStrVec[i]) + 1;
    Utils_Malloc((void **)(&key), prefixLen);
    snprintf(key, prefixLen, PWD_PREFIX_FMT, PWD_PREFIX, prefixStrVec[i], prefix);
    if (PWD_DEBUG) {
      debug_print("Pwd_Store write key '%s', ", key);
      Utils_PrintCharArray(stderr, " val: ", (unsigned char *)pwdStr);
      debug_print("%s", "\n");
    }
    if (SecureStorage_AddItem(storage, (unsigned char *)key, strlen(key), (unsigned char *)pwdStr, strLen) == false) {
      Utils_CreateAndCopyString(&err, errStr, strlen(errStr));
      snprintf(errStr, sizeof(errStr), "Can't add item '%s' to storage, error %s", key, err);
      Utils_Free(err);
      Utils_Free(pwdStr);
      Utils_Free(key);
      return false;
    }
    Utils_Free(key);
    Utils_Free(pwdStr);
  }
  return storeOldPasswords(p, storage, prefix);
}

STATIC bool loadOldPasswords(PwdS *pwd, const SecureStorageS *storage, const char *prefix) {
  int16_t i = 0, len = 0, prefixLen = 0;
  char *key = NULL, *err = NULL;
  unsigned char *val = NULL;

  if (pwd == NULL || storage == NULL) {
    assert(LIB_NAME "Password structure and storage structure must not be NULL" && (false || Pwd_TestMode));
    return false;
  }
  if (Utils_IsPrefixValid("Pwd:loadOldPasswords", prefix) == false) return false;
  prefixLen = strlen(prefix) + strlen(PWD_OLD_PWD_LEN_PREFIX) + 1;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, PWD_OLD_P_LEN_PREFIX_FMT, PWD_OLD_PWD_LEN_PREFIX, prefix);
  if (SecureStorage_GetItem(storage, (unsigned char *)key, strlen(key), &val) == false) {
    snprintf(errStr, sizeof(errStr), "Can't get item '%s' from storage, error %s", key, err);
    debug_print("Internal Error: Read from secure storage key '%s' not found\n", key);
    Utils_Free(key);
    return false;
  }
  len = atoi((char *)val);
  debug_print("num of old passwords %d\n", len);
  Utils_Free(key);
  Utils_Free(val);
  if (len == 0) return true;
  prefixLen = strlen(prefix) + strlen(PWD_OLD_PWD_PREFIX) + 5; // 5 is for the integer length and for the string
  Utils_Malloc((void **)(&key), prefixLen);
  for (i = 0; i < len; i++) {
    snprintf(key, prefixLen, PWD_OLD_P_PREFIX_FMT, PWD_OLD_PWD_PREFIX, i, prefix);
    if (SecureStorage_GetItem(storage, (unsigned char *)key, strlen(key), &val) == false) {
      snprintf(errStr, sizeof(errStr), "Can't get item '%s' from storage, error %s", key, err);
      Utils_Free(key);
      return false;
    }
    if (PWD_DEBUG) {
      debug_print("Pwd_Load read old passwords key '%s', ", key);
      Utils_PrintCharArray(stderr, " val:\n", val);
      debug_print("%s", "\n");
    }
    pwd->OldHashedPasswords[i] = val;
  }
  Utils_Free(key);
  return true;
}

bool Pwd_Load(void **loadPwd, const SecureStorageS *storage, const char *prefix, char **retName) {
  int16_t i = 0, pwdLen = 0, saltLen = 0, prefixLen = 0;
  bool ret = false, temporaryPwd = false;
  MicroSecTimeStamp expiration = 0;
  char *val = NULL, *key = NULL;
  unsigned char *pwd = NULL, *salt = NULL;
  const char *prefixStrVec[NUM_OF_STRUCTS] = { PWD_PASS_PREFIX, PWD_SALT_PREFIX, PWD_OTHER_PREFIX };
  int32_t errorsCounter = 0;

  *retName = NULL;
  if (storage == NULL) {
    snprintf(errStr, sizeof(errStr), "Storage must initiated first");
    return false;
  }
  if (Utils_IsPrefixValid("Pwd_Load", prefix) == false) return false;
  for (i = 0; i < NUM_OF_STRUCTS; i++) {
    prefixLen = strlen(prefix) + strlen(PWD_PREFIX) + strlen(prefixStrVec[i]) + 1;
    Utils_Malloc((void **)(&key), prefixLen);
    snprintf(key, prefixLen, PWD_PREFIX_FMT, PWD_PREFIX, prefixStrVec[i], prefix);
    if (SecureStorage_GetItem(storage, (unsigned char *)key, strlen(key), (unsigned char **)&val) == false) {
      snprintf(errStr, sizeof(errStr), "Internal Error: Read from secure storage key '%s' not found", key);
      debug_print("Internal Error: Read from secure storage key '%s' not found\n", key);
      Utils_Free(key);
      return false;
    }
    if (PWD_DEBUG) {
      debug_print("Pwd_Load read key '%s', ", key);
      Utils_PrintCharArray(stderr, " val: ", (unsigned char *)val);
      debug_print("%s", "\n");
    }
    if (i == OTHER_STRUCT_IDX) {
      int tmp, tmpCounter, scanLen = 0;
      uint32_t tmpExp0 = 0, tmpExp1 = 0;
      if ((scanLen = sscanf(val, PWD_OTHER_STRUCT_SCAN_FMT, &tmpCounter, &tmp, &tmpExp0, &tmpExp1)) != 4) {
        snprintf(errStr, sizeof(errStr), "Internal error in Pwd_Load: scanf of '%s' must return exactly 4 parameters, but read %d", val, scanLen);
        Utils_Abort(errStr);
        Utils_Free(key);
        Utils_Free(val);
        return false;
      }
      temporaryPwd = tmp;
      errorsCounter = tmpCounter;
      expiration = (MicroSecTimeStamp)(((uint64_t)tmpExp0) << 32) + tmpExp1;
    } else {
      if (i == PASS_STRUCT_IDX) {
        Utils_GetCharArrayLen((unsigned char *)val, &pwdLen, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
        Utils_CreateAndCopyUcString(&pwd, (unsigned char *)val, pwdLen + UTILS_STR_LEN_SIZE);
      } else if (i == SALT_STRUCT_IDX) {
        Utils_GetCharArrayLen((unsigned char *)val, &saltLen, MIN_SALT_LEN, MAX_SALT_LEN);
        Utils_CreateAndCopyUcString(&salt, (unsigned char *)val, saltLen + UTILS_STR_LEN_SIZE);
      }
    }
    Utils_Free(key);
    Utils_Free(val);
  }
  if (PWD_DEBUG) {
    debug_print("Load data for pwd: %d %d %" MY_PRId64 "\n", (int16_t)errorsCounter, (int16_t)temporaryPwd, (int32_t)(expiration >> 32), (int32_t)expiration);
    Utils_PrintHexStr(stderr, "Loaded pwd: ", pwd, pwdLen);
    Utils_PrintHexStr(stderr, "Loaded salt: ", salt, saltLen);
  }
  if (newUserPwdHandler((PwdS **)loadPwd, pwd, pwdLen, salt, saltLen, true) == false) { // the loaded password is already hashed
    printf("Error: %s\n", errStr);
    Utils_Free(pwd);
    Utils_Free(salt);
    return false;
  }
  Utils_Free(pwd);
  Utils_Free(salt);
  (*((PwdS **)loadPwd))->Expiration = expiration;
  (*((PwdS **)loadPwd))->ErrorsCounter = errorsCounter;
  (*((PwdS **)loadPwd))->TemporaryPwd = temporaryPwd;
  ret = loadOldPasswords(*loadPwd, storage, prefix);
  if (PWD_DEBUG && ret == true) {
    Pwd_Print(stderr, "loaded pwd:\n", *(PwdS **)loadPwd);
  }
  if (ret == false) Pwd_FreeUserPwd(loadPwd);
  return ret;
}

bool Pwd_IsEqual(const void *pwdS1, const void *pwdS2) {
  int16_t i = 0;
  bool ret = true;
  const PwdS *pwd1 = NULL, *pwd2 = NULL;

  if (pwdS1 == NULL && pwdS2 == NULL) return true;
  if (pwdS1 == NULL || pwdS2 == NULL) return false;
  pwd1 = (const PwdS *)pwdS1;
  pwd2 = (const PwdS *)pwdS2;
  debug_print("Pwd_IsEqual %d %d %d %d\n", pwd1->TemporaryPwd == pwd2->TemporaryPwd, pwd1->ErrorsCounter == pwd2->ErrorsCounter,
    Utils_CharArrayCmp(pwd1->hashPassword, pwd2->hashPassword), Utils_CharArrayCmp(pwd1->caSalt, pwd2->caSalt));
  for (i = 0; i < DEFAULT_NUMBER_OF_OLD_PASSWORDS; i++) {
    if ((pwd1->OldHashedPasswords[i] == NULL && pwd2->OldHashedPasswords[i] != NULL) ||
        (pwd1->OldHashedPasswords[i] != NULL && pwd2->OldHashedPasswords[i] == NULL) ||
        Utils_CharArrayCmp(pwd1->OldHashedPasswords[i], pwd2->OldHashedPasswords[i]) == false) {
      ret = false;
      break;
    }
  }
  return (ret && pwd1->TemporaryPwd == pwd2->TemporaryPwd && pwd1->Expiration == pwd2->Expiration && pwd1->ErrorsCounter == pwd2->ErrorsCounter &&
          Utils_CharArrayCmp(pwd1->hashPassword, pwd2->hashPassword) == true && Utils_CharArrayCmp(pwd1->caSalt, pwd2->caSalt) == true);
}
