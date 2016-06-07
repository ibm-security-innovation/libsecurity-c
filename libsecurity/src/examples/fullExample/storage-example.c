#include "example.h"

const unsigned char *StorageSecret = ((const unsigned char *)"12345678123456781234567812345678");
const unsigned char *StorageSalt = ((const unsigned char *)"abcd");

static bool storeToFile(EntityManager *entityManager, const char *fileName, const unsigned char *secret, const unsigned char *salt) {
  bool pass=false;

  pass = EntityManager_Store(entityManager, fileName, secret, salt);
  if (pass == false) {
    printf("Error while storing data to file '%s', error %s\n", fileName, errStr);
  }
  return pass;
}

static bool loadFromFile(EntityManager *entityManager, const char *fileName, const unsigned char *secret, const unsigned char *salt) {
  bool pass=false;

    pass = EntityManager_Load(&(entityManager), fileName, secret, salt);
    if (pass == false) {
      printf("Error while loading data from file '%s', error %s\n", fileName, errStr);
    }
  return pass;
}

bool StoreData(EntityManager *entityManager) {
  bool pass = true;
  const char *fileName = "store.txt";
  EntityManager e1;
  EntityManager *loadedEntityManager;

  EntityManager_New(&e1);
  loadedEntityManager = &e1;
  if (storeToFile(entityManager, fileName, StorageSecret, StorageSalt) == true) {
	  if (loadFromFile(loadedEntityManager, fileName, StorageSecret, StorageSalt) == true) {
	    if (EntityManager_IsEqual(entityManager, loadedEntityManager) == false) {
	      printf("Stored data != loaded one");
	      EntityManager_PrintFull(stdout, "Stored data:", entityManager);
	      EntityManager_PrintFull(stdout, "Loaded data:", loadedEntityManager);
	      pass = false;
	    }else {
	      EntityManager_PrintFull(stdout, "Loaded data is equal to the stored one:", loadedEntityManager);
		    pass = true;
	    }
		  EntityManager_FreeAll(loadedEntityManager);
	  }else
	  	pass = false;
//	  Utils_RemoveFile(fileName);
  }else
  	pass = false;
  return pass;
}
