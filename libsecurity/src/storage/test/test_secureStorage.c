#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "libsecurity/utils/crypto.h"
#include "libsecurity/utils/utils.h"
#include "libsecurity/utils/itemsList.h"
#include "libsecurity/utils/fileAdapters.h"
#include "libsecurity/storage/secureStorage_int.h"

#define NUM_OF_USERS 4

#define SECRET ((unsigned char *)"12345678901234561234567890123456")
#define SALT ((unsigned char *)"The salt")

#define KEY_FMT "Key:%d"

static unsigned char testIvStr[FULL_IV_LEN + 1];

// Verify that valid storage return NULL
// Verify that invalid storage parameters (name or secret) return an eror
STATIC bool testAddStorage() {
  int16_t i, j, len, secretLen = KEY_VAL_MAX_STR_LEN;
  bool pass = true, ret;
  unsigned char secret[secretLen + 10];
  char *salts[] = { "", NULL, "abc" };
  SecureStorageS storage;

  len = sizeof(salts) / sizeof(char *);
  for (i = 0; i < len; i++) {
    strcpy((char *)secret, "");
    for (j = 0; j < secretLen - 1; j++) {
      ret = SecureStorage_NewStorage(secret, (unsigned char *)salts[i], &storage);
      if (ret == true && (i == 1 || (j != SECRET_LEN))) {
        printf("Test testAddStorage failed, secure storage was generated for invalid parameters: salt = '%s', secret length = %d\n", salts[i], j);
        pass = false;
      } else if (ret == false && i != 1 && j == SECRET_LEN) {
        printf("Test testAddStorage failed, secure storage was not generated for legal parameters: "
               "salt = '%s', secret length = %d, error: %s\n",
               salts[i], j, errStr);
        pass = false;
      }
      if (ret == true) SecureStorage_FreeStorage(&storage);
      strcat((char *)secret, "a");
    }
  }
  return pass;
}

// Verify that added key is in the storage while other key is not
// Verify that added and removed key is not in the storage
// Verify that added the same key with different value return the new value
STATIC bool testAddRemoveItemToStorage() {
  bool ret, pass = true;
  SecureStorageS storage;
  unsigned char *keys[] = { (unsigned char *)"key1", (unsigned char *)"key2" };
  unsigned char *values[] = { (unsigned char *)"val1", (unsigned char *)"val2" };
  int16_t lens[2] = { 4, 4 }; // to save some code
  unsigned char *val;

  SecureStorage_NewStorage(SECRET, SALT, &storage);
  SecureStorage_AddItem(&storage, keys[0], lens[0], values[0], lens[0]);
  ret = SecureStorage_GetItem(&storage, keys[0], lens[0], &val);
  if (ret == true && strcmp((char *)values[0], (char *)val) != 0) {
    printf("Test testAddRemoveItemToStorage failed: The value received for key '%s' was '%s' but "
           "expected to '%s', error: %s\n",
           keys[0], val, values[0], errStr);
    pass = false;
  }
  if (ret == true) Utils_Free(val);
  ret = SecureStorage_GetItem(&storage, keys[1], lens[0], &val);
  if (ret == true) {
    printf("Test testAddRemoveItemToStorage failed: Received value '%s' for key '%s' that is not in the storage\n", val, keys[1]);
    pass = false;
    Utils_Free(val);
  }
  SecureStorage_RemoveItem(&storage, keys[0], lens[0]);
  ret = SecureStorage_GetItem(&storage, keys[0], lens[0], &val);
  if (ret == true) {
    printf("Test testAddRemooveItemToStorage failed: Received value '%s' for key '%s' that was already removed from the storage\n", val, keys[0]);
    pass = false;
    Utils_Free(val);
  }
  SecureStorage_AddItem(&storage, keys[0], lens[0], values[1], lens[1]);
  ret = SecureStorage_GetItem(&storage, keys[0], lens[0], &val);
  if (ret == true && strcmp((char *)values[1], (char *)val) != 0) {
    printf("Test testAddRemoveItemToStorage failed: The value received for key '%s' was '%s' but expected to '%s'\n", keys[0], val, values[1]);
    pass = false;
  }
  if (ret == true) Utils_Free(val);
  SecureStorage_RemoveItem(&storage, keys[0], lens[0]);
  SecureStorage_FreeStorage(&storage);
  return pass;
}

// Create a secure storage
// Save it to disk, read it and verify that it is the same as the stored one
// Change some of the file data and verify that the new storage signature is not valid
STATIC bool testCreateSaveReadSecureStorage() {
  int16_t i;
  bool pass = true, ret[2];
  SecureStorageS storage, storage1;
  unsigned char *keys[4] = { (unsigned char *)"key1 to be or not to be and "
                                              "'key1 to be or not to be :)'",
                             (unsigned char *)"key2", (unsigned char *)"key3 and other keys",
                             (unsigned char *)"key4 this is the question" };
  unsigned char *values[4] = { (unsigned char *)"val1-1", (unsigned char *)"val2", (unsigned char *)"val3", (unsigned char *)"val4 :)" };
  int16_t dataLen = 0, cnt = 0, valuesLen = 0;
  unsigned char *val;
  char *fileName = "tmp.data", *fileNameErr = "tmp.err";

  dataLen = sizeof(keys) / sizeof(unsigned char *);
  SecureStorage_NewStorage(SECRET, SALT, &storage);
  for (i = 0; i < dataLen; i++) {
    valuesLen = (int16_t)strlen((char *)values[i]);
    ret[0] = SecureStorage_AddItem(&storage, keys[i], strlen((char *)keys[i]), values[i], valuesLen);
    ret[1] = SecureStorage_GetItem(&storage, keys[i], strlen((char *)keys[i]), &val);
    if (ret[0] == true && ret[1] == false) {
      printf("Test testCreateSaveReadSecureStorage failed: Error while try to get added key '%s', error: %s\n", keys[i], errStr);
      pass = false;
    } else if (ret[1] == false || (ret[1] == true && strcmp((char *)values[i], (char *)val) != 0)) {
      printf("Test testCreateSaveReadSecureStorage failed: The value received for key '%s' was '%s' but expected to '%s'\n", keys[i], val, values[i]);
      pass = false;
    }
    if (ret[1] == true) Utils_Free(val);
  }
  if (SecureStorage_StoreSecureStorageToFile(fileName, &storage) == false) {
    printf("Test testCreateSaveReadSecureStorage failed: can't store to file '%s', error: %s\n", fileName, errStr);
    pass = false;
  }
  if (SecureStorage_LoadSecureStorageFromFile(fileName, SECRET, SALT, &storage1) == false) {
    printf("Test testCreateSaveReadSecureStorage failed: can't load from file '%s', error: %s\n", fileName, errStr);
    pass = false;
  }
  for (i = dataLen - 1; i >= 0; i--) {
    ret[0] = SecureStorage_GetItem(&storage1, keys[i], strlen((char *)keys[i]), &val);
    if (ret[0] == false) {
      printf("Test testCreateSaveReadSecureStorage failed: Reading saved storage, key '%s' was not found in data base, error: %s\n", keys[i], errStr);
      pass = false;
    } else if (strcmp((char *)values[i], (char *)val) != 0) {
      printf("Test testCreateSaveReadSecureStorage failed: Reading saved storage, The value received for key '%s' was '%s' but expected to '%s'\n",
      keys[i], val, values[i]);
      pass = false;
    }
    if (ret[0] == true) Utils_Free(val);
  }
  if (Utils_CharArrayCmp(storage.caSalt, storage1.caSalt) == false || Utils_CharArrayCmp(storage.caSecret, storage1.caSecret) == false ||
      Utils_CharArrayCmp(storage.caSign, storage1.caSign) == false) {
    printf("Test testCreateSaveReadSecureStorage failed: Reading saved storage, The save and load files headers are differt:\n");
    Utils_PrintCharArray(stderr, "salt1: ", storage.caSalt);
    Utils_PrintCharArray(stderr, "salt2: ", storage1.caSalt);
    Utils_PrintCharArray(stderr, "secret1: ", storage.caSecret);
    Utils_PrintCharArray(stderr, "secret2: ", storage1.caSecret);
    Utils_PrintCharArray(stderr, "sign1: ", storage.caSign);
    Utils_PrintCharArray(stderr, "sign2: ", storage1.caSign);
    pass = false;
  }
  SecureStorage_FreeStorage(&storage1);
  if (pass == true) {
    // printf("Now to corrupted file\n");
    for (i = 0; i < 30; i++) {
      cnt = 0;
      bool changeWasDone = false;
      FILE *ifp = FileAdapters_Fopen(fileName, "r");
      FILE *ofp = FileAdapters_Fopen(fileNameErr, "w");
      char str[ERR_STR_LEN];
      int16_t maxLen = ERR_STR_LEN, idx = 0;
      while (fgets(str, maxLen, ifp) != NULL) {
        if (cnt++ == i) {
          idx = strlen(str);
          str[idx - 1] = 'l';
          str[idx / 2] = 'a';
          changeWasDone = true;
        }
        fprintf(ofp, "%s", str);
      }
      FileAdapters_Fclose(ifp);
      FileAdapters_Fclose(ofp);
      if (changeWasDone == true) {
        ret[0] = SecureStorage_LoadSecureStorageFromFile(fileNameErr, SECRET, SALT, &storage1);
        if (ret[0] == true) {
          printf("Test testCreateSaveReadSecureStorage failed: touched secure storage file pass the signature test, idx %d\n", i);
          pass = false;
        }
        SecureStorage_FreeStorage(&storage1);
      }
      if (pass == false) break;
    }
  }
  for (i = 0; i < dataLen; i++) {
    SecureStorage_RemoveItem(&storage, keys[i], strlen((char *)keys[i]));
  }
  SecureStorage_FreeStorage(&storage);
  if (SECURE_DEBUG == false) {
    FileAdapters_Remove(fileName);
    FileAdapters_Remove(fileNameErr);
  }
  return pass;
}

// Verify that added/removed/find key with wrong length will return an error
STATIC bool testAddFindRemoveNotValidItemsToStorage() {
  int16_t i = 0, j = 0, step = 1, maxKeyLen = 0, maxValLen = 0, testLen = KEY_VAL_MAX_STR_LEN + 10, maxLen = 0, saltLen = 0;
  bool breakFlag = false, pass = true, ret = false;
  SecureStorageS storage;
  unsigned char str[KEY_VAL_MAX_STR_LEN * 2], *str1 = (unsigned char *)"abc", *tmpVal = NULL;
  int16_t str1Len = 0;

  str1Len = strlen((char *)str1);
  maxLen = min(KEY_VAL_MAX_STR_LEN, NaCl_MAX_TEXT_LEN_BYTES - UTILS_STR_LEN_SIZE);
  step = maxLen / 10;
  SecureStorage_NewStorage(SECRET, SALT, &storage);
  if (READABLE_STORAGE == true)
    saltLen = 0;
  else if (Utils_GetCharArrayLen(storage.caSalt, &saltLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN) == false)
    return false;
  maxValLen = maxLen - ALIGN_FACTOR;
  maxKeyLen = maxValLen - saltLen;
  memcpy(str, "", 1);
  for (i = 0; i < testLen; i += step) {
    ret = SecureStorage_AddItem(&storage, str, i, str1, str1Len);
    if (ret == true && (i == 0 || i > maxKeyLen)) {
      printf("Test testAddFindRemoveNotValidItemsToStorage failed, Add illegal item to secure storage, key length = %d, max length %d\n", i, maxKeyLen);
      pass = false;
      breakFlag = true;
    } else if (ret == false && i <= maxKeyLen && i != 0) {
      printf("Test testAddFindRemoveNotValidItemsToStorage failed, Adding legal key length %d to secure storage failed, error: %s\n", i, errStr);
      pass = false;
      breakFlag = true;
    }
    ret = SecureStorage_AddItem(&storage, str1, str1Len, str, i);
    if (ret == true && (i == 0 || i > maxValLen)) {
      printf("Test testAddFindRemoveNotValidItemsToStorage failed, Add illegal item to secure "
             "storage, val length = %d, max length %d, salt len %d, max string len %d, align len %d, salt '%s'\n",
             i, maxValLen, saltLen, maxLen, ALIGN_FACTOR, storage.caSalt);
      pass = false;
      breakFlag = true;
    } else if (ret == false && i <= maxValLen && i != 0) {
      printf("Test testAddFindRemoveNotValidItemsToStorage failed, Adding legal val length %d, max "
             "val length %d,  to secure storage failed, error: %s\n",
             i, maxValLen, errStr);
      pass = false;
      breakFlag = true;
    }
    ret = SecureStorage_GetItem(&storage, str, i, &tmpVal);
    if (ret == true && (i == 0 || i > maxKeyLen)) {
      printf("Test testAddFindRemoveNotValidItemsToStorage failed, Get item with illegal key length = %d, value: '%s'\n", i, tmpVal);
      breakFlag = true;
      pass = false;
    } else if (ret == false && i <= maxKeyLen && i != 0) {
      printf("Test testAddFindRemoveNotValidItemsToStorage failed, Get item with legal key length "
             "%d from secure storage failed, error: %s\n",
             i, errStr);
      pass = false;
      breakFlag = true;
    }
    if (ret == true) Utils_Free(tmpVal);
    ret = SecureStorage_RemoveItem(&storage, str, i);
    if (ret == true && (i == 0 || i > maxKeyLen)) {
      printf("Test testAddFindRemoveNotValidItemsToStorage failed, Remove item with illegal key length = %d\n", i);
      breakFlag = true;
      pass = false;
    } else if (ret == false && i <= maxKeyLen && i != 0) {
      printf("Test testAddFindRemoveNotValidItemsToStorage failed, Remove item with legal key length %d failed, error: %s\n", i, errStr);
      breakFlag = true;
      pass = false;
    }
    if (breakFlag == true) {
      break; // may add storage print
    }
    SecureStorage_RemoveItem(&storage, str1, str1Len);
    for (j = 0; j < step; j++)
      strcat((char *)str, "a");
  }
  SecureStorage_FreeStorage(&storage);
  return pass;
}

// Verify for string length X-longest aloowed string + X:
//  The same value is return when the same string encrypted twice
//  The encrypt and than decrypt of a string is equal to the original string
// Verify that invalid decrypted string results in error
STATIC bool testEncryptDecrypt() {
  int16_t i, len, textLen, textLen1;
  bool pass = true, breakFlag = false;
  char *testText = "015this is a text:";
  unsigned char *encKey, *encKey1, *val;
  int16_t ret[3];
  char text[KEY_VAL_MAX_STR_LEN * 2] = { 0 }, charArray[10];

  Utils_GetCharArrayLen((unsigned char *)testText, &textLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN);
  // done by the = {0} memset(text, 0, KEY_VAL_MAX_STR_LEN*2);
  memcpy(text, testText, textLen + UTILS_STR_LEN_SIZE);
  len = KEY_VAL_MAX_STR_LEN + 2;
  for (i = 0; i < len; i++) {
    ret[0] = encrypt((unsigned char *)text, testIvStr, SECRET, &encKey);
    ret[1] = encrypt((unsigned char *)text, testIvStr, SECRET, &encKey1);
    if (strlen(text) > NaCl_MAX_TEXT_LEN_BYTES) {
      if (ret[0] == true) {
        printf("Test testEncryptDecrypt failed, idx: %d, Successfully encrypted too long text %d\n", i, (int16_t)strlen(text));
        pass = false;
        if (ret[0] == true) Utils_Free(encKey);
        if (ret[1] == true) Utils_Free(encKey1);
        break;
      } else
        continue;
    }
    Utils_GetCharArrayLen(encKey, &textLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN);
    Utils_GetCharArrayLen(encKey1, &textLen1, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN);
    if (textLen != textLen1 || memcmp(encKey + UTILS_STR_LEN_SIZE, encKey1 + UTILS_STR_LEN_SIZE, textLen) != 0) {
      printf("Test testEncryptDecrypt failed, idx: %d, Encrypted text '%s'\n", i, text);
      printf("Test testEncryptDecrypt failed, idx: %d, Encrypted text '%s' (len %d) encKey '%s' "
             "(len %d) != 2'nd encrypted text '%s' (%d)\n",
             i, text, (int16_t)strlen(text), encKey + UTILS_STR_LEN_SIZE, textLen, encKey1 + UTILS_STR_LEN_SIZE, textLen1);
      pass = false;
      if (ret[0] == true) Utils_Free(encKey);
      if (ret[1] == true) Utils_Free(encKey1);
      break;
    }
    if (ret[1] == true) Utils_Free(encKey1);
    ret[2] = decrypt(encKey, SECRET, &val);
    if (ret[2] == true && memcmp(val, text, strlen(text)) != 0 && strlen(text) < KEY_VAL_MAX_STR_LEN) {
      Utils_GetCharArrayLen(val, &textLen, KEY_VAL_MIN_STR_LEN, KEY_VAL_MAX_STR_LEN);
      printf("Test testEncryptDecrypt failed, idx: %d, Encrypted text '%s' (len %d, %s) != decrypted text '%s' (len %d)\n", i, text,
             (int16_t)strlen(text), encKey, val, textLen);
      pass = false;
      breakFlag = true;
    }
    if (ret[2] == true) Utils_Free(val);
    if (ret[0] == true) Utils_Free(encKey);
    if (breakFlag == true) break;
    sprintf(charArray, "%c", 'a' + i);
    strcat(text, charArray);
    Utils_SetCharArrayLen((unsigned char *)text, strlen(text) - UTILS_STR_LEN_SIZE);
  }
  return pass;
}

STATIC bool testStorageCorners() {
  bool pass = true;
  unsigned char *data = (unsigned char *)"abc123";
  unsigned char *tmp;
  SecureStorageS storage;

  SecureStorage_NewStorage(SECRET, SALT, &storage);
  if (SecureStorage_AddItem(NULL, data, 6, data, 6) == true || SecureStorage_AddItem(&storage, NULL, 6, data, 6) == true ||
      SecureStorage_AddItem(&storage, data, 6, NULL, 6) == true || SecureStorage_GetItem(&storage, NULL, 1, &tmp) == true ||
      SecureStorage_GetItem(NULL, data, 6, &tmp) == true || SecureStorage_RemoveItem(NULL, data, 6) == true ||
      SecureStorage_RemoveItem(&storage, NULL, 6) == true) {
    printf("Test testStorageCorners failed, function with NUKK parameters retur true\n");
    pass = false;
  }
  SecureStorage_FreeStorage(&storage);
  return pass;
}

STATIC void freeHash(htab *t) {
  while (hcount(t)) {
    Utils_Free(hkey(t));
    Utils_Free(hstuff(t));
    hdel(t);
  }
  hdestroy(t);
}

STATIC void init() {
  int16_t i = 0;

  for (i = 0; i < IV_LEN; i++) {
    testIvStr[i + UTILS_STR_LEN_SIZE] = (char)('0' + i % 10);
  }
  Utils_SetCharArrayLen(testIvStr, IV_LEN);
}

#ifdef MBED_OS
int16_t testStorage()
#else
int main()
#endif
{
  bool pass = true;
  // secureStorageTestMode = true;
  int16_t i = 0, len = 0;
  char *res = NULL;

  init();
  Storage_TestMode = true;
  Utils_TestFuncS callFunc[] = { 
                                 { "testAddStorage", testAddStorage },
                                 { "testEncryptDecrypt", testEncryptDecrypt },
                                 { "testAddRemoveItemToStorage", testAddRemoveItemToStorage },
                                 { "testCreateSaveReadSecureStorage", testCreateSaveReadSecureStorage },
                                 { "testAddFindRemoveNotValidItemsToStorage", testAddFindRemoveNotValidItemsToStorage },
                                 { "testStorageCorners", testStorageCorners } 
                               };

  len = sizeof(callFunc) / sizeof(Utils_TestFuncS);
  for (i = 0; i < len; i++) {
    if ((callFunc[i]).testFunc() == false) {
      res = "fail";
      pass = false;
    } else
      res = "pass";
    printf("Test %s:'%s' %s\n", __FILE__, callFunc[i].name, res);
  }
  //  EntityManager_RemoveRegisteredPropertyList();
  return pass;
}
