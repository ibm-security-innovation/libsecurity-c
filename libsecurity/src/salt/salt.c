// Package salt : The salt package provides salting services for anyone who uses passwords

#include "libsecurity/salt/salt_int.h"

bool Salt_TestMode = false;

void Salt_Print(FILE *ofp, const char *header, const SaltS *salt) {
  if (header != NULL) fprintf(ofp, "%s", header);
  if (salt == NULL) return;
  fprintf(ofp, "Salt info: secret: '%s', salt: '%s', iterations: %d, output len: %d\n", salt->caSecret, salt->caSalt, salt->Iterations, salt->OutputLen);
}

STATIC bool isValidOutputLen(int16_t val) {
  if (val < MIN_OUTPUT_LEN || val > MAX_OUTPUT_LEN) {
    snprintf(errStr, sizeof(errStr), "Error: Salt struct is not valid, the used output length %d must be between %d-%d", val, MIN_OUTPUT_LEN, MAX_OUTPUT_LEN);
    assert(LIB_NAME "Salt structure, output length is not valid" && (false || Salt_TestMode));
    return false;
  }
  return true;
}

STATIC bool isValidSaltSecret(const unsigned char *caSecret) {
  int16_t len = 0;

  if (caSecret == NULL) {
    assert(LIB_NAME "Salt secret string must not be NULL" && (false || Salt_TestMode));
    return false;
  }
  Utils_GetCharArrayLen(caSecret, &len, MIN_SECRET_LEN, MAX_SECRET_LEN);
  if (len < MIN_SECRET_LEN || len > MAX_SECRET_LEN) {
    snprintf(errStr, sizeof(errStr), "Error: Secret string has illegal length %d, length must be between %d and %d", len, MIN_SECRET_LEN, MAX_SECRET_LEN);
    return false;
  }
  return true;
}

STATIC bool isValidSalt(const unsigned char *caSalt) {
  int16_t len = 0;

  if (caSalt == NULL) {
    assert(LIB_NAME "Salt string must not be NULL" && (false || Salt_TestMode));
    return false;
  }
  Utils_GetCharArrayLen(caSalt, &len, MIN_SALT_LEN, MAX_SALT_LEN);
  if (len < MIN_SALT_LEN || len > MAX_SALT_LEN) {
    snprintf(errStr, sizeof(errStr), "Error: Salt string has illegal length %d, length must be between %d and %d", len, MIN_SALT_LEN, MAX_SALT_LEN);
    return false;
  }
  return true;
}

STATIC bool isValidNumOfIterations(int16_t val) {
  if (val < MIN_NUM_OF_ITERATIONS) {
    snprintf(errStr, sizeof(errStr), "Error: Salt struct is not valid, the number of itterations %d "
                                     "is less than the minimum %d",
             val, MIN_NUM_OF_ITERATIONS);
    assert(LIB_NAME "Number of iterations is not valid" && (false || Salt_TestMode));
    return false;
  }
  return true;
}

bool Salt_IsValid(const SaltS *salt) {
  if (salt == NULL) {
    snprintf(errStr, sizeof(errStr), "Salt_IsValid: salt structure must not be NULL");
    return false;
  }
  if (isValidSaltSecret(salt->caSecret) == false || isValidSalt(salt->caSalt) == false || isValidOutputLen(salt->OutputLen) == false ||
      isValidNumOfIterations(salt->Iterations) == false) {
    return false;
  }
  return true;
}

// The default Salt: use sha1, output length 16 bytes
bool Salt_NewSalt(SaltS **newSalt, const unsigned char *sSecret, const unsigned char *sSalt) {
  unsigned char *caSecret = NULL, *caSalt = NULL;

  if (newSalt == NULL || sSecret == NULL || sSalt == NULL) {
    snprintf(errStr, sizeof(errStr), "Salt_NewSalt: secret and salt strings must not be NULL");
    return false;
  }
  Utils_GenerateCharArray(sSecret, (int16_t)strlen((const char *)sSecret), &caSecret);
  if (isValidSaltSecret(caSecret) == false) {
    Utils_Free(caSecret);
    return false;
  }
  Utils_GenerateCharArray(sSalt, (int16_t)strlen((const char *)sSalt), &caSalt);
  if (isValidSalt(caSalt) == false) {
    Utils_Free(caSecret);
    Utils_Free(caSalt);
    return false;
  }
  Utils_Malloc((void **)(newSalt), sizeof(SaltS));
  (*newSalt)->caSecret = caSecret;
  (*newSalt)->caSalt = caSalt;
  (*newSalt)->OutputLen = DEFAULT_OUTPUT_LEN;
  (*newSalt)->Iterations = DEFAULT_NUM_OF_ITERATIONS;
  return true;
}

void Salt_FreeSalt(SaltS *salt) {
  if (salt == NULL) return;
  Utils_Free(salt->caSecret);
  Utils_Free(salt->caSalt);
  Utils_Free(salt);
}

STATIC bool getRandomSalt(int16_t len, unsigned char **caNewSalt) {
  unsigned char *ptr = NULL;

  if (len < MIN_SALT_LEN || len > MAX_SALT_LEN) {
    snprintf(errStr, sizeof(errStr), "Error: required random salt size was %d, must be between %d-%d", len, MIN_SALT_LEN, MAX_SALT_LEN);
    assert(LIB_NAME "Salt length must be valid" && (false || Salt_TestMode));
    return false;
  }
  Utils_Malloc((void **)caNewSalt, len + 1 + UTILS_STR_LEN_SIZE);
  ptr = *caNewSalt;
  ptr += UTILS_STR_LEN_SIZE;
  Crypto_Random(ptr, len);
  Utils_SetCharArrayLen(*caNewSalt, len);
  return true;
}

// Return the encrypted data for a given salt and secret
// The way to add salt is: secret + salt
bool Salt_Generate(const SaltS *salt, unsigned char **caNewPwd) {
  int16_t i = 0, iter = 0, cnt = 0, len = 0, secretLen = 0, saltLen = 0;
  unsigned char *data = NULL, *ptr = NULL;
  unsigned char digest[crypto_hash_BYTES];

  if (salt == NULL || caNewPwd == NULL) return false;
  if (Salt_IsValid(salt) == false) {
    return false;
  }
  len = crypto_hash_BYTES;
  Utils_GetCharArrayLen(salt->caSecret, &secretLen, MIN_SECRET_LEN, MAX_SECRET_LEN);
  if (secretLen > crypto_hash_BYTES) len = secretLen;
  Utils_GetCharArrayLen(salt->caSalt, &saltLen, MIN_SALT_LEN, MAX_SALT_LEN);
  len += saltLen;
  Utils_Malloc((void **)(&data), len + 1);
  len = secretLen + saltLen;
  ptr = &(salt->caSecret[UTILS_STR_LEN_SIZE]);
  for (iter = 0; iter < salt->Iterations; iter++) {
    cnt = 0;
    for (i = 0; i < len; i++) {
      if (i < crypto_hash_BYTES && (i < secretLen || iter > 0))
        data[i] = ptr[i];
      else if (cnt < saltLen)
        data[i] = salt->caSalt[UTILS_STR_LEN_SIZE + cnt++];
    }
    Crypto_SHA256(data, len, digest);
    len = saltLen + crypto_hash_BYTES;
    ptr = digest;
  }
  len = (int16_t)crypto_hash_BYTES;
  if (len > salt->OutputLen) {
    len = salt->OutputLen;
  }
  Utils_Malloc((void **)(caNewPwd), len + 1 + UTILS_STR_LEN_SIZE);
  for (i = 0; i < crypto_hash_BYTES && i < salt->OutputLen; i++) {
    (*caNewPwd)[i + UTILS_STR_LEN_SIZE] = digest[i];
  }
  Utils_SetCharArrayLen(*caNewPwd, len);
  (*caNewPwd)[len + UTILS_STR_LEN_SIZE] = 0;
  Utils_Free(data);
  return true;
}

// Return a generated salted password and the used salt from a given password
bool Salt_GenerateSaltedPassword(const unsigned char *sPwd, const unsigned char *sSalt, bool randomSalt, int16_t randomSaltLen, unsigned char **caNewPwd) {
  bool ret = false;
  unsigned char *newSalt = NULL;
  SaltS *s = NULL;

  if (sPwd == NULL || sSalt == NULL || caNewPwd == NULL || (randomSaltLen < 0 && randomSalt == true)) return false;
  if (randomSalt) {
    if (getRandomSalt(randomSaltLen, &newSalt) == false) return false;
  } else {
    Utils_CreateAndCopyUcString(&newSalt, sSalt, (int16_t)strlen((const char *)sSalt));
  }
  if (Salt_NewSalt(&s, sPwd, newSalt) == false) {
    Utils_Free(newSalt);
    return false;
  }
  ret = Salt_Generate(s, caNewPwd);
  Utils_Free(newSalt);
  Salt_FreeSalt(s);
  return ret;
}

bool Salt_GenerateCharArraySaltedPassword(const unsigned char *caPwd, const unsigned char *caSalt, unsigned char **caNewPwd) {
  int16_t saltLen = 0, pwdLen = 0;

  if (caPwd == NULL || caSalt == NULL || caNewPwd == NULL) return false;
  if (Utils_GetCharArrayLen(caPwd, &pwdLen, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == false ||
      Utils_GetCharArrayLen(caSalt, &saltLen, MIN_SALT_LEN, MAX_SALT_LEN) == false)
    return false;
  return Salt_GenerateSaltedPassword(caPwd + UTILS_STR_LEN_SIZE, caSalt + UTILS_STR_LEN_SIZE, false, 0, caNewPwd);
}

bool Salt_IsEqual(const SaltS *s1, const unsigned char *caPwd) {
  bool ok = false;
  unsigned char *newPwd = NULL;

  if (s1 == NULL || caPwd == NULL || isValidSaltSecret(caPwd) == false) return false;
  if (Salt_Generate(s1, &newPwd) == false) {
    snprintf(errStr, sizeof(errStr), "Error: Can't generate password for salt");
    return false;
  }
  ok = Utils_CharArrayCmp(caPwd, newPwd);
  Utils_Free(newPwd);
  return ok;
}
