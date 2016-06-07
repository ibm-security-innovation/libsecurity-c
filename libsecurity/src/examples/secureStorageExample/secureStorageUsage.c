#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/storage/secureStorage.h"
#include "libsecurity/entity/entityManager.h"
#include "libsecurity/password/password.h"

static bool addWiFiInfoToStorage(SecureStorageS *storage, int16_t numOfItems, const unsigned char *keys[], const unsigned char *values[]) {
  int16_t i = 0;
  bool pass = true;

  for (i=0 ; i<numOfItems ; i++) {
    if (SecureStorage_AddItem(storage, keys[i], (int32_t) strlen((const char *)keys[i]), values[i], (int32_t) strlen((const char *)values[i])) == false) {
      printf("Error while adding key '%s' with value '%s' to the storage, erorr %s\n", keys[i], values[i], errStr);
      return false;
    }
  }
  return pass;
}

static bool storeToFile(const char *fileName, SecureStorageS *storage) {
    if (SecureStorage_StoreSecureStorageToFile(fileName, storage) == false) {
      printf("storeToFile failed: can't store to file '%s', error: %s\n", fileName, errStr);
      return false;
    }
    return true;
}

static bool loadFromFileAndVerifyData(const char *fileName, const unsigned char *storageSecret, const unsigned char *storageSalt, int16_t numOfItems, const unsigned char *keys[], const unsigned char *values[]){
  int16_t i=0;
  bool pass=true;
  unsigned char *val=NULL;
  SecureStorageS storage;

  if (SecureStorage_LoadSecureStorageFromFile(fileName, storageSecret, storageSalt, &storage) == false) {
    printf("loadFromFileAndVerifyData failed: can't load from file '%s', error: %s\n", fileName, errStr);
    return false;
  }
  // Loading the secure storage from file and verifing its authenticity
  for (i=0 ; i<numOfItems ; i++) {
    if (SecureStorage_GetItem(&storage, keys[i], (int32_t) strlen((const char *)keys[i]), &val) == false) {
      printf("loadFromFileAndVerifyData failed: Can't read key '%s' from the storage, error: %s\n", keys[i], errStr);
      pass = false;
      break;
    }
    if (strcmp((const char *)values[i], (char *)val) != 0) {
      printf("loadFromFileAndVerifyData failed: The value received for key '%s' was '%s' but '%s' was expected, error: %s\n",
           keys[i], val, values[i], errStr);
      pass = false;
    }
    Utils_Free(val);
    if (pass== false)
      break;
  }
  SecureStorage_FreeStorage(&storage);
  return pass;
}

int main(void) {
  int16_t len=0;
  SecureStorageS storage;
  bool pass = false;
  const unsigned char *keys[] = { (const unsigned char *) "HomeWifiPassword", (const unsigned char *) "WorkWifiPassword" };
  const unsigned char *values[] = { (const unsigned char *)"home1@#4", (const unsigned char *)"MoreCompl3cated!@" };
  const char *fileName = "myStorage.txt";
  unsigned char *storageSecret = NULL;
  const unsigned char *storageSalt = ((const unsigned char *)"The salt");

  if (Utils_GenerateNewValidPassword(&storageSecret, SECRET_LEN) == false) {
    printf("Fatal error: can't generate a new valid password, error: %s\n", errStr);
    return false;
  }
  printf("This example shows how to store a wifi password to a secure storage\n");
  printf("The rationale behind this example is that saving a password as clear text may result with the password being stolen putting your home or work wifi under threat of being abused\n");
  printf("Through this example each key and password are stored after encryption using AES algorithm\n");
  printf("Before storing the secure storage to a file, it is signed to ensure that it won't be compromised\n\n");
  len = sizeof(keys) / sizeof (unsigned char *);
  if (SecureStorage_NewStorage(storageSecret, storageSalt, &storage) == false) {
    printf("SecureStorage_NewStorage failed, error %s\n", errStr);
    return false;
  }
  if (addWiFiInfoToStorage(&storage, len, keys, values) &&
      storeToFile(fileName, &storage) &&
      loadFromFileAndVerifyData(fileName, storageSecret, storageSalt, len, keys, values)) {
    pass = true;
  }
  Utils_Free(storageSecret);
  SecureStorage_FreeStorage(&storage);
  return pass;
}