// Package storage : The secureStorage package provides implementation of Secure storage services: Persistence mechanism based on AES
// Encryption of key-value pairs within a signed file.
//
// The secure storgae allows maintaining data persistently and securely.
//  The implementation of the secure storage is based on encrypted key-value pairs that are stored
//   in signed files to guarantee that the data is not altered or corrupted.
//  - Both the key and the value are encrypted when they are added to the storage using an Advanced Encryption Standard (AES) algorithm.
//  - Each time a new secure storage is generated, a secret supplied by the user accompanies it
//    and is used in all HMAC and AES calculations related to that storage. To make it difficult for a third party to decipher or use the
//    stored data,
//    Cipher Block Chaining (CBC) mode is used to ensure that multiple independent encryptions of the same data with the same key have
//    different results.
//    That is, when a block with the same piece of plain text is encrypted with the same key, the result is always different.
//  - To implement a time efficient secure storage with keys, that is, to identify keys that are
//    already stored without decrypting the entire storage, and when such a key is identified replacing its value, a two step mechanism is
//    used.
//    The first time a key is introduced, a new IV is drawn, the key is 'HMAC'ed with the secret and is stored with the IV as the value (1st
//    step).
//    The original key is encrypted with the drawn IV and stored again, this time with the value that is encrypted with its own random IV
//    (2nd step).
//    The next time that same key is stored, the algorithm, identifies that it already exists in the storage, pulls out the random IV that
//    was stored in the 1st step,
//    finds the 2nd step storage of that key and replaces its value with the new encrypted one.
//  - To guarantee that the data is not altered or corrupted, the storage is signed using HMAC. The signature is added to the secure
//  storage. When the storage is loaded,
//    the HMAC is calculated and compared with the stored signature to verify that the file is genuine.

#include "libsecurity/storage/secureStorage_int.h"

bool Storage_TestMode = false;

STATIC void calcHashXor(unsigned char *dst, const unsigned char *in, int16_t len) {
  int16_t i = 0, loopLen = 0;

  if (dst == NULL || in == NULL) {
    assert(LIB_NAME "Input and output strings must not be NULL" && (false || Storage_TestMode));
  }
  loopLen = min(SHA256_LEN, len);
  for (i = 0; i < loopLen; i++) {
    dst[i] = dst[i] ^ in[i];
  }
}

STATIC bool calcHash(const SecureStorageS *storage, unsigned char *hash) {
  int16_t i = 0, len = 0, secretLen = 0;
  htab *t = NULL;
  unsigned char tmpHash[SHA256_LEN], cHash[crypto_auth_BYTES];
  unsigned char *data = NULL;

  if (storage == NULL || hash == NULL) {
    assert(LIB_NAME "Storage structure and hash string must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  t = storage->Data;
  memset(hash, 0, SHA256_LEN);
  if (hfirst(t)) {
    do {
      for (i = 0; i < 2; i++) {
        if (i == 0)
          data = (unsigned char *)hkey(t);
        else
          data = (unsigned char *)hstuff(t);
        if (Utils_GetCharArrayLen(data, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) return false;
        len += UTILS_STR_LEN_SIZE;
        if (Utils_GetCharArrayLen(storage->caSecret, &secretLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) {
          return false;
        }
        Crypto_CalcHmac(&(storage->caSecret[UTILS_STR_LEN_SIZE]), secretLen, data, len, cHash);
        memcpy(tmpHash, cHash, SHA256_LEN);
        calcHashXor(hash, tmpHash, crypto_auth_BYTES);
      }
    } while (hnext(t));
  }
  return true;
}

STATIC bool getValue(htab *t, const unsigned char *key, unsigned char **val) {
  int16_t len = 0;

  if (t == NULL || key == NULL) {
    assert(LIB_NAME "Hash structure and key string must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  if (Utils_GetCharArrayLen(key, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) return false;
  len += UTILS_STR_LEN_SIZE;
  if (hfind(t, key, len) == false) {
    return false;
  }
  if (Utils_GetCharArrayLen((unsigned char *)hstuff(t), &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) return false;
  Utils_CreateAndCopyUcString(val, (unsigned char *)hstuff(t), len + UTILS_STR_LEN_SIZE);
  return true;
}

STATIC bool clearKey(const SecureStorageS *storage, const unsigned char *key) {
  int16_t len = 0;
  htab *t = NULL;

  if (storage == NULL || key == NULL) {
    assert(LIB_NAME "Storage structure and key string must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  t = storage->Data;
  if (Utils_GetCharArrayLen(key, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) return false;
  if (key != NULL && hfind(t, key, len + UTILS_STR_LEN_SIZE) == true) { // override existing item
    Utils_Free(hkey(t));
    Utils_Free(hstuff(t));
    hdel(t);
    return true;
  }
  return false;
}

STATIC void freeData(htab *t) {
  if (t == NULL) return;
  while (hcount(t)) {
    Utils_Free(hkey(t));
    Utils_Free(hstuff(t));
    hdel(t);
  }
  hdestroy(t);
}

STATIC bool updateData(const SecureStorageS *storage, const unsigned char *key, const unsigned char *val) {
  int16_t kLen = 0, vLen = 0;
  unsigned char *keyStr = NULL, *valStr = NULL;
  htab *t = NULL;

  if (storage == NULL || key == NULL || val == NULL) {
    assert(LIB_NAME "Storage structure and key, value strings must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  t = storage->Data;
  clearKey(storage, key);
  if (Utils_GetCharArrayLen(key, &kLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false ||
      Utils_GetCharArrayLen(val, &vLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false)
    return false;
  if (hadd(t, key, kLen + UTILS_STR_LEN_SIZE, val)) {
    Utils_CreateAndCopyUcString(&keyStr, key, kLen + UTILS_STR_LEN_SIZE);
    hkey(t) = keyStr;
    Utils_CreateAndCopyUcString(&valStr, val, vLen + UTILS_STR_LEN_SIZE);
    hstuff(t) = valStr;
  } else {
    printf("Internal error: item: %s must be free\n", key);
    return false;
  }
  return true;
}

STATIC bool isSaltValid(const unsigned char *caSalt) {
  int16_t len = 0;

  if (caSalt == NULL) {
    assert(LIB_NAME "Salt string must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  if (Utils_GetCharArrayLen(caSalt, &len, MIN_SALT_LEN, KEY_VAL_MAX_STR_LEN) == false) { // salt can be empty string
    return false;
  }
  return true;
}

STATIC bool isSecretValid(const unsigned char *caSecret) {
  int16_t len = 0;

  if (caSecret == NULL) {
    assert(LIB_NAME "Secret string must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  if (Utils_GetCharArrayLen(caSecret, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) {
    return false;
  }
  // in NaCl it must be at least 32, so the common is exactly 32B
  if (len != SECRET_LEN) {
    snprintf(errStr, sizeof(errStr), "AES key length is not valid (%d), secret length must be exactly %d Bytes", len, SECRET_LEN);
    return false;
  }
  return true;
}

STATIC bool isLengthValid(const unsigned char *caStr, int16_t minLen, int16_t maxLen) {
  int16_t len = 0;

  if (caStr == NULL) {
    len = 0;
    assert(LIB_NAME "Input string must not be NULL" && (false || Storage_TestMode));
  } else {
    if (Utils_GetCharArrayLen(caStr, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) return false;
  }
  if (caStr == NULL || minLen > len || len > maxLen) {
    snprintf(errStr, sizeof(errStr), "Error: number of characters %d in '%s' must be between %d-%d", len, caStr, minLen, maxLen);
    return false;
  }
  return true;
}

STATIC bool isDataValid(const unsigned char *caSecret, const unsigned char *caSalt) {
  if (isSaltValid(caSalt) == false) {
    return false;
  }
  return isSecretValid(caSecret);
}

void SecureStorage_FreeStorage(void *s) {
  SecureStorageS *storage = NULL;

  if (s == NULL) return;
  storage = (SecureStorageS *)s;
  Utils_Free(storage->caSalt);
  Utils_Free(storage->caSecret);
  freeData(storage->Data);
}

bool SecureStorage_NewStorage(const unsigned char *sSecret, const unsigned char *sSalt, SecureStorageS *storage) {
  unsigned char *secretStr = NULL, *saltStr = NULL;
  const char *sign = "N.A.";

  if (storage == NULL || sSecret == NULL || sSalt == NULL) {
    snprintf(errStr, sizeof(errStr), "SecureStorage_NewStorage: Storage, secret and salt must not be NULL");
    return false;
  }
  Utils_GenerateCharArray(sSecret, strlen((const char *)sSecret), &secretStr);
  Utils_GenerateCharArray(sSalt, strlen((const char *)sSalt), &saltStr);
  if (isDataValid(secretStr, saltStr) == false) {
    Utils_Free(secretStr);
    Utils_Free(saltStr);
    return false;
  }
  memcpy(storage->caSign, sign, strlen(sign) + 1);
  storage->Data = hcreate(H_TAB_SIZE);
  storage->caSecret = secretStr;
  storage->caSalt = saltStr;
  return true;
}

// The encrypted string structure: len, IV, encrypted string IV structure: len + I
// Encrypted string structure: len + text
// Note: the caller must free the memory
STATIC bool encrypt(const unsigned char *caText, const unsigned char *ivStr, const unsigned char *caSecret, unsigned char **caData) {
  int16_t textLen = 0, longLen = 0;
  unsigned char *startEncTextptr = NULL;
  const unsigned char *ivStrPtr = NULL;

  *caData = NULL;
  if (caText == NULL || caSecret == NULL || ivStr == NULL) {
    assert(LIB_NAME "Input text, initiation vector and secret strings must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  if (Utils_GetCharArrayLen(caText, &textLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) return false;
  textLen += UTILS_STR_LEN_SIZE;
  textLen += Crypto_GetAesPadFactor(textLen);
  if (textLen > NaCl_MAX_TEXT_LEN_BYTES) {
    snprintf(errStr, sizeof(errStr), "The text length %d is too long for NaCl, maximum length must be %d", textLen, NaCl_MAX_TEXT_LEN_BYTES);
    return false;
  }
  longLen = textLen;
  // both the encrypted and the ivStr have prefix of UTILS_STR_LEN_SIZE
  Utils_Malloc((void **)(caData), UTILS_STR_LEN_SIZE + FULL_IV_LEN + textLen + 1);
  // done by Utils_Malloc memset(*data, 0,
  // UTILS_STR_LEN_SIZE+FULL_IV_LEN+textLen);
  startEncTextptr = *caData + UTILS_STR_LEN_SIZE + FULL_IV_LEN;
  memcpy(*caData + UTILS_STR_LEN_SIZE, ivStr, FULL_IV_LEN);
  ivStrPtr = (const unsigned char *)(ivStr + UTILS_STR_LEN_SIZE);
  if (Crypto_EncryptDecryptAesCbc(CRYPTO_ENCRYPT_MODE, longLen, &(caSecret[UTILS_STR_LEN_SIZE]), SECRET_LEN, ivStrPtr, caText, startEncTextptr) == false) {
    return false;
  }
  Utils_SetCharArrayLen(*caData, FULL_IV_LEN + textLen);
  return true;
}

// The text to decrypt structure: len, IV, decrepted text ivStr structure: len, iv decrypted text structure: len, text
// Note: the caller must free the memory
STATIC bool decrypt(unsigned char *caText, const unsigned char *caSecret, unsigned char **caData) {
  int16_t len = 0, textLen = 0, longLen = 0;
  unsigned char *ptr = NULL, *textPtr = NULL;
  unsigned char ivStr[IV_LEN + 1];

  if (caText == NULL || caSecret == NULL) {
    assert(LIB_NAME "TExt and secret strings must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  if (Utils_GetCharArrayLen((unsigned char *)caText, &len, KEY_VAL_MIN_STR_LEN + FULL_IV_LEN, KEY_VAL_MAX_STR_LEN) == false) return false;
  // both the encrypted and the IV have UTILS_STR_LEN_SIZE
  textLen = len - FULL_IV_LEN;
  longLen = textLen;
  Utils_Malloc((void **)caData, textLen + 1);
  // done by Utils_Malloc memset(*data, 0, textLen+1);
  // the iv str have its length in the prefix
  ptr = caText + UTILS_STR_LEN_SIZE + UTILS_STR_LEN_SIZE;
  memcpy(ivStr, ptr, IV_LEN);
  ivStr[IV_LEN] = 0;
  textPtr = *caData;
  ptr = caText + UTILS_STR_LEN_SIZE + FULL_IV_LEN;
  if (Crypto_EncryptDecryptAesCbc(CRYPTO_DECRYPT_MODE, longLen, &(caSecret[UTILS_STR_LEN_SIZE]), SECRET_LEN, ivStr, ptr, textPtr) == false) {
    return false;
  }
  return true;
}

STATIC void getHKey(const unsigned char *caKey, unsigned char *cahKey) {
  int16_t len;
  const unsigned char *keyPtr = NULL;
  unsigned char hash[crypto_hash_BYTES]; // to avoid NaCl problems

  if (caKey == NULL) {
    assert(LIB_NAME "Input key string must not be NULL" && (false || Storage_TestMode));
    return;
  }
  memset(cahKey, 0, SHA256_LEN);
  if (Utils_GetCharArrayLen(caKey, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) return;
  keyPtr = (const unsigned char *)(caKey + UTILS_STR_LEN_SIZE);
  Crypto_SHA256(keyPtr, len, hash);
  memcpy(cahKey + UTILS_STR_LEN_SIZE, hash, SHA256_LEN);
  cahKey[SHA256_LEN + UTILS_STR_LEN_SIZE] = 0;
  Utils_SetCharArrayLen(cahKey, SHA256_LEN);
  if (SECURE_DEBUG) {
    Utils_PrintHexStr(stderr, "Hash of key ", caKey, len + UTILS_STR_LEN_SIZE);
    Utils_PrintHexStr(stderr, "is ", cahKey, SHA256_LEN + UTILS_STR_LEN_SIZE);
  }
}

STATIC bool getRandomFromKey(const SecureStorageS *storage, const unsigned char *caKey, char unsigned *cahKey, unsigned char **carKey) {
  int16_t ret = 0, len = 0;
  htab *t = NULL;

  if (storage == NULL || caKey == NULL) {
    assert(LIB_NAME "Storage structure and key string must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  t = storage->Data;
  getHKey(caKey, cahKey);
  ret = getValue(t, cahKey, carKey);
  if (ret == false) {
    if (SECURE_DEBUG) {
      Utils_PrintHexStr(stderr, "Random from key not found ", cahKey, SHA256_LEN);
    }
    return false;
  }
  if (SECURE_DEBUG) {
    Utils_GetCharArrayLen(caKey, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN);
    Utils_PrintHexStr(stderr, "Random of key ", caKey, len);
    Utils_PrintHexStr(stderr, "Is ", *carKey, IV_LEN + UTILS_STR_LEN_SIZE);
  }
  return true;
}

STATIC void generateRandomToKey(const unsigned char *key, unsigned char *hKey, unsigned char *rKey) {
  unsigned char random[IV_LEN + 1]; // in NaCl the IV len is fixed

  if (key == NULL) {
    assert(LIB_NAME "Input key string must not be NULL" && (false || Storage_TestMode));
    return;
  }
  getHKey(key, hKey);
  Crypto_Random(random, IV_LEN);
  memcpy(rKey + UTILS_STR_LEN_SIZE, random, IV_LEN);
  rKey[IV_LEN + UTILS_STR_LEN_SIZE] = 0;
  Utils_SetCharArrayLen(rKey, IV_LEN);
}

STATIC bool generateAlignedCharAray(const unsigned char *input, int16_t len, unsigned char *salt, int16_t saltLen, unsigned char **caOutput) {
  int16_t newLen = 0;
  unsigned char *tStr = NULL;

  if (input == NULL) {
    assert(LIB_NAME "Input string must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  if (len < 0) {
    snprintf(errStr, sizeof(errStr), "generateAlignedCharAray: string length must be positive");
    assert(LIB_NAME "Input length must be positive" && (false || Storage_TestMode));
    return false;
  }
  newLen = len + saltLen + Crypto_GetAesPadFactor(len + saltLen + UTILS_STR_LEN_SIZE);
#ifdef MBEDTLS_CRYPTO
  newLen += UTILS_STR_LEN_SIZE;
#endif
  if (newLen < ALIGN_FACTOR) newLen += ALIGN_FACTOR; // for string with length of 0
  Utils_Malloc((void **)(&tStr), newLen + 1);
  // done by Utils_Malloc memset(tStr, 0, newLen+1);
  if (saltLen > 0) memcpy(tStr, salt + UTILS_STR_LEN_SIZE, saltLen);
  memcpy(tStr + saltLen, input, len);
  Utils_GenerateCharArray(tStr, newLen - ALIGN_FACTOR, caOutput);
  Utils_Free(tStr);
  return true;
}

bool SecureStorage_AddItem(const SecureStorageS *storage, const unsigned char *sKey, int16_t keyLen, const unsigned char *sVal, int16_t valLen) {
  int16_t len = 0, saltLen = 0;
  bool keyWasAlreadyStored = false;
  unsigned char *caEncKey = NULL, *caEncVal = NULL, *caKey = NULL, *caVal = NULL;
  unsigned char cahKey[SHA256_LEN + UTILS_STR_LEN_SIZE + 1], rKey[FULL_IV_LEN + 1], rKey1[FULL_IV_LEN + 1];
  unsigned char *tKey = NULL;

  if (storage == NULL || sKey == NULL || sVal == NULL) {
    snprintf(errStr, sizeof(errStr), "SecureStorage_AddItem: Storage, key and value must not be NULL");
    return false;
  }
  if (keyLen <= 0 || valLen <= 0) {
    snprintf(errStr, sizeof(errStr), "SecureStorage_AddItem: key len %d and val len %d must be positives\n", keyLen, valLen);
    return false;
  }
  if (READABLE_STORAGE == true)
    saltLen = 0;
  else if (Utils_GetCharArrayLen(storage->caSalt, &saltLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false)
    return false;
  if (isSecretValid(storage->caSecret) == false) return false;
  if (generateAlignedCharAray(sKey, keyLen, storage->caSalt, saltLen, &caKey) == false) return false;
  if (generateAlignedCharAray(sVal, valLen, NULL, 0, &caVal) == false) {
    Utils_Free(caKey);
    return false;
  }
  if (isLengthValid(caKey, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN - 1) == false ||
      isLengthValid(caVal, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN - 1) == false) {
    Utils_Free(caKey);
    Utils_Free(caVal);
    return false;
  }
  keyWasAlreadyStored = getRandomFromKey(storage, caKey, cahKey, &tKey);
  if (SECURE_DEBUG && keyWasAlreadyStored == true) {
    Utils_PrintHexStr(stderr, "random of key ", tKey, SHA256_LEN);
  }
  if (keyWasAlreadyStored) {
    memcpy(rKey, tKey, FULL_IV_LEN);
    rKey[FULL_IV_LEN] = 0;
    Utils_Free(tKey);
  } else {
    generateRandomToKey(caKey, cahKey, rKey);
    if (SECURE_DEBUG) {
      Utils_PrintHexStr(stderr, "Generate random of key ", rKey, SHA256_LEN);
    }
  }
  debug_print("Encrypt key '%s', val '%s', secret '%s'\n", caKey, caVal, storage->caSecret);
  if (SECURE_DEBUG) {
    Utils_PrintHexStr(stderr, "Use random of key ", rKey, SHA256_LEN);
  }
  if (encrypt(caKey, rKey, storage->caSecret, &caEncKey) == false) {
    Utils_Free(caKey);
    Utils_Free(caVal);
    return false;
  }
  Crypto_Random(rKey1 + UTILS_STR_LEN_SIZE, IV_LEN);
  Utils_SetCharArrayLen(rKey1, IV_LEN);
  if (encrypt(caVal, rKey1, storage->caSecret, &caEncVal) == false) {
    Utils_Free(caKey);
    Utils_Free(caVal);
    Utils_Free(caEncKey);
    return false;
  }
  debug_print("Add key: usedKey: %d, key '%s', val '%s'\n", keyWasAlreadyStored, caKey, caVal);
  Utils_Free(caKey);
  Utils_Free(caVal);
  if (Utils_GetCharArrayLen(caEncKey, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) return false;
  if (keyWasAlreadyStored != true) {
    updateData(storage, cahKey, rKey);
    if (SECURE_DEBUG) {
      Utils_PrintHexStr(stderr, "Add hash key:", cahKey, SHA256_LEN + UTILS_STR_LEN_SIZE);
      Utils_PrintHexStr(stderr, "And random:", rKey, FULL_IV_LEN);
    }
  }
  updateData(storage, caEncKey, caEncVal);
  Utils_Free(caEncKey);
  Utils_Free(caEncVal);
  return true;
}

bool SecureStorage_GetItem(const SecureStorageS *storage, const unsigned char *sKey, int16_t keyLen, unsigned char **sVal) {
  int16_t len = 0, saltLen = 0;
  bool ret = false;
  unsigned char *caEncKey = NULL, *caEncVal = NULL, *rKey = NULL, *caKey = NULL, *caVal = NULL;
  unsigned char cahKey[SHA256_LEN + UTILS_STR_LEN_SIZE + 1];
  htab *t = NULL;

  if (storage == NULL || sKey == NULL || sVal == NULL) {
    snprintf(errStr, sizeof(errStr), "SecureStorage_GetItem: Storage and key must not be NULL");
    return false;
  }
  *sVal = NULL;
  if (keyLen <= 0) {
    snprintf(errStr, sizeof(errStr), "SecureStorage_GetItem: key len %d must be positive\n", keyLen);
    return false;
  }
  t = storage->Data;
  if (READABLE_STORAGE == true)
    saltLen = 0;
  else if (Utils_GetCharArrayLen(storage->caSalt, &saltLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false)
    return false;
  if (generateAlignedCharAray(sKey, keyLen, storage->caSalt, saltLen, &caKey) == false) return false;
  if (isLengthValid(caKey, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN - 1) == false ||
      Utils_GetCharArrayLen(caKey, &len, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) {
    Utils_Free(caKey);
    return false;
  }
  if (getRandomFromKey(storage, caKey, cahKey, &rKey) == false) {
    Utils_Free(caKey);
    return false;
  }
  if (SECURE_DEBUG) {
    Utils_PrintHexStr(stderr, "Get hash key:", cahKey, SHA256_LEN + UTILS_STR_LEN_SIZE);
  }
  ret = encrypt(caKey, rKey, storage->caSecret, &caEncKey);
  Utils_Free(rKey);
  if (ret == false) {
    Utils_Free(caKey);
    return false;
  }
  ret = getValue(t, caEncKey, &caEncVal);
  Utils_Free(caEncKey);
  if (ret == false) {
    snprintf(errStr, sizeof(errStr), "Error: key '%s' was not found", caKey);
    Utils_Free(caKey);
    return false;
  }
  Utils_Free(caKey);
  ret = decrypt(caEncVal, storage->caSecret, &caVal);
  Utils_ConvertCharArrayToStr(caVal, sVal);
  debug_print("The val '%s'\n", *sVal);
  Utils_Free(caEncVal);
  Utils_Free(caVal);
  return ret;
}

bool SecureStorage_RemoveItem(const SecureStorageS *storage, const unsigned char *sKey, int16_t keyLen) {
  int16_t saltLen = 0;
  bool ret = false, ret1 = false;
  unsigned char *caEncKey = NULL, *rKey = NULL, *caKey = NULL;
  unsigned char cahKey[SHA256_LEN + UTILS_STR_LEN_SIZE + 1];

  if (storage == NULL || sKey == NULL) {
    snprintf(errStr, sizeof(errStr), "SecureStorage_RemoveItem: Storage and key must not be NULL");
    return false;
  }
  if (keyLen <= 0) {
    snprintf(errStr, sizeof(errStr), "SecureStorage_RemoveItem: key len %d must be positives\n", keyLen);
    return false;
  }
  if (READABLE_STORAGE == true)
    saltLen = 0;
  else if (Utils_GetCharArrayLen(storage->caSalt, &saltLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false)
    return false;
  if (generateAlignedCharAray(sKey, keyLen, storage->caSalt, saltLen, &caKey) == false) return false;
  if (isLengthValid(caKey, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN - 1) == false || getRandomFromKey(storage, caKey, cahKey, &rKey) == false) {
    Utils_Free(caKey);
    return false;
  }
  ret1 = clearKey(storage, cahKey);
  if (ret1 == false) { // continue to try to remove the "real" key value
    snprintf(errStr, sizeof(errStr), "Error: key for random '%s' was not found", cahKey);
  }
  ret = encrypt(caKey, rKey, storage->caSecret, &caEncKey);
  Utils_Free(rKey);
  if (ret == false) {
    Utils_Free(caKey);
    return false;
  }
  if (clearKey(storage, caEncKey) == false) {
    Utils_Free(caEncKey);
    snprintf(errStr, sizeof(errStr), "Error: key '%s' was not found", caKey);
    return false;
  }
  Utils_Free(caKey);
  Utils_Free(caEncKey);
  return ret1;
}

STATIC bool calcHMac(const SecureStorageS *storage, unsigned char *caData) {
  unsigned char tmpHash[SHA256_LEN], hash[SHA256_LEN];
  int16_t len = 0;
  int16_t secretLen = 0;

  if (storage == NULL) {
    assert(LIB_NAME "Storage structure must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  memset(hash, 0, SHA256_LEN);
  calcHash(storage, hash);
  if (SECURE_DEBUG) {
    Utils_PrintHexStr(stderr, "Base hash:", hash, SHA256_LEN);
  }
  Utils_GetCharArrayLen(storage->caSalt, &len, MIN_SALT_LEN, KEY_VAL_MAX_STR_LEN);

  if (Utils_GetCharArrayLen(storage->caSecret, &secretLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false) {
    return false;
  }
  if (Crypto_CalcHmac(&(storage->caSecret[UTILS_STR_LEN_SIZE]), secretLen, storage->caSalt, len + UTILS_STR_LEN_SIZE, tmpHash) == false)
    return false;
  calcHashXor(hash, tmpHash, SHA256_LEN);
  memcpy(caData + UTILS_STR_LEN_SIZE, hash, SHA256_LEN);
  Utils_SetCharArrayLen(caData, SHA256_LEN);
  caData[SIGN_LEN] = 0;
  return true;
}

STATIC bool writeHeader(FILE *fp, SecureStorageS *storage) {
  if (storage == NULL || storage->caSalt == NULL) {
    assert(LIB_NAME "Storage structure and storage salt string must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  if (Utils_WriteCharArray(fp, storage->caSalt) == false) return false;
  if (Utils_WriteCharArray(fp, storage->caSign) == false) return false;
  debug_print("Write to file: salt: '%s', signature '%s'\n", storage->caSalt, storage->caSign);
  return true;
}

STATIC bool readHeader(FILE *fp, SecureStorageS *storage) {
  unsigned char caSign[KEY_VAL_MAX_STR_LEN], caSalt[KEY_VAL_MAX_STR_LEN];
  int16_t len = 0;

  if (storage == NULL) {
    assert(LIB_NAME "Storage structure must not be NULL" && (false || Storage_TestMode));
  }
  if (Utils_ReadCharArray(fp, caSalt, KEY_VAL_MAX_STR_LEN) == false) {
    return false;
  }
  if (Utils_ReadCharArray(fp, caSign, KEY_VAL_MAX_STR_LEN) == false) {
    return false;
  }
  debug_print("Read from file: salt: '%s', signature '%s'\n", caSalt, caSign);
  Utils_GetCharArrayLen(caSalt, &len, MIN_SALT_LEN, KEY_VAL_MAX_STR_LEN);
  memcpy(storage->caSalt, caSalt, len + UTILS_STR_LEN_SIZE + 1);
  memcpy(storage->caSign, caSign, SIGN_LEN + 1);
  return true;
}

STATIC void printDecryptedData(const char *header, unsigned char *caKey, unsigned char *caVal, const unsigned char *caSecret) {
  int16_t keyLen = 0, valLen = 0;
  unsigned char *dKey = NULL, *dVal = NULL;

  if (caKey == NULL || caVal == false) {
    assert(LIB_NAME "Key and value strings must not be NULL" && (false || Storage_TestMode));
    return;
  }
  if (Utils_GetCharArrayLen(caKey, &keyLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false ||
      Utils_GetCharArrayLen(caVal, &valLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false)
    return;
  if (decrypt(caKey, caSecret, &dKey) == false) return;
  if (decrypt(caVal, caSecret, &dVal) == false) {
    Utils_Free(dKey);
    return;
  }
  if (keyLen != SHA256_LEN || valLen != IV_LEN) {
      printf("%s key '%s', val '%s'\n", header, dKey, dVal);
  }
  Utils_Free(dKey);
  Utils_Free(dVal);
}

// Handling the hash and the random entries:
//   Both are not encrypted and not hex represented in the table therefore,
//   they must be converted to hex representation and
//   are saved with prefix to be destinguest when reading the file
STATIC void writeKeyValue(FILE *fp, const SecureStorageS *storage) {
  htab *t = NULL;

  if (storage == NULL) {
    assert(LIB_NAME "Storage structure must not be NULL" && (false || Storage_TestMode));
    return;
  }
  t = storage->Data;
  fprintf(fp, TOTAL_STR_FMT, (int)hcount(t)); // number of items in the hash
  debug_print("Total number of items to write %d\n", (int16_t)hcount(t));
  if (hfirst(t)) {
    do {
      Utils_WriteCharArray(fp, (unsigned char *)hkey(t));
      Utils_WriteCharArray(fp, (unsigned char *)hstuff(t));
      if (SECURE_DEBUG) {
        printDecryptedData("write:", (unsigned char *)hkey(t), (unsigned char *)hstuff(t), storage->caSecret);
      }
    } while (hnext(t));
  }
}

STATIC bool readKeyValue(FILE *fp, const SecureStorageS *storage) {
  int16_t i = 0;
  int total = 0; // write/read is symetrical for each length
  char strLen[TOTAL_AND_NUMBER_STR_LEN];
  unsigned char caKey[KEY_VAL_MAX_STR_LEN], caVal[KEY_VAL_MAX_STR_LEN];

  if (storage == NULL) {
    assert(LIB_NAME "Storage structure must not be NULL" && (false || Storage_TestMode));
    return false;
  }
  snprintf(errStr, sizeof(errStr), "File is not valid"); // the default error
  if (Utils_Fgets(strLen, TOTAL_AND_NUMBER_STR_LEN, fp) == NULL) {
    return false;
  }
  if (sscanf(strLen, TOTAL_STR_FMT, &total) != 1) {
    return false;
  }
  debug_print("Total number of items to read %d\n", total);
  for (i = 0; i < total; i++) {
    if (Utils_ReadCharArray(fp, caKey, KEY_VAL_MAX_STR_LEN) == false || 
        Utils_ReadCharArray(fp, caVal, KEY_VAL_MAX_STR_LEN) == false) {
      return false;
    }
    if (SECURE_DEBUG) {
      printDecryptedData("read:", caKey, caVal, storage->caSecret);
    }
    updateData(storage, caKey, caVal);
  }
  snprintf(errStr, sizeof(errStr), "No error"); // the default error
  return true;
}

bool SecureStorage_StoreSecureStorageToFile(const char *fileName, SecureStorageS *storage) {
  FILE *ofp = NULL;

  if (storage == NULL || fileName == NULL) {
    snprintf(errStr, sizeof(errStr), "Storage and file name must initiated first");
    return false;
  }
  if (calcHMac(storage, storage->caSign) == false) {
    return false;
  }
  ofp = FileAdapters_Fopen(fileName, "w");
  if (ofp == NULL) {
    snprintf(errStr, sizeof(errStr), "Attempt to write the Secure storage to file '%s' failed", fileName);
    return false;
  }
  if (writeHeader(ofp, storage) == false) return false;
  writeKeyValue(ofp, storage);
  FileAdapters_Fclose(ofp);
  return true;
}

bool SecureStorage_LoadSecureStorageFromFile(const char *fileName, const unsigned char *sSecret, const unsigned char *sSalt, SecureStorageS *storage) {
  bool ret = false;
  unsigned char hash[SIGN_LEN + 1];
  FILE *ifp = NULL;

  if (storage == NULL || fileName == NULL || sSecret == NULL || sSalt == NULL) {
    snprintf(errStr, sizeof(errStr), "SecureStorage_LoadSecureStorageFromFile: Storage, file name, secret and salt must not be NULL");
    return false;
  }
  ifp = FileAdapters_Fopen(fileName, "r");
  if (ifp == NULL) {
    snprintf(errStr, sizeof(errStr), "Attempt to read Secure storage file '%s' failed", fileName);
    return false;
  }
  if (SecureStorage_NewStorage(sSecret, sSalt, storage) == false) return false;
  if (readHeader(ifp, storage) == false) return false;
  ret = readKeyValue(ifp, storage);
  FileAdapters_Fclose(ifp);
  if (ret == false && Storage_TestMode == false) {
    printf("%s\n", errStr);
    return false;
  }
  calcHMac(storage, hash);
  if (memcmp(hash, storage->caSign, SIGN_LEN) != 0) {
    snprintf(errStr, sizeof(errStr), "ERROR: Calculated signature != read signature\n");
    return false;
  } else {
    debug_print("%s", "File OK: signature match\n");
  }
  return true;
}
