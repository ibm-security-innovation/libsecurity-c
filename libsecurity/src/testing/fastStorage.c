#include "parser_int.h"

#define FAST_STORAGE_MAX_STORAGES	4
SecureStorageS internalStorage[FAST_STORAGE_MAX_STORAGES];
int32_t storageWasInit[FAST_STORAGE_MAX_STORAGES] = {false, false, false, false};

#define FAST_STORAGE_NEW_IDX 			(FAST_STORAGE_IDX_OFFSET+0)		// R
#define FAST_STORAGE_FREE_IDX 			(FAST_STORAGE_IDX_OFFSET+1)		// S
#define FAST_STORAGE_ADD_ITEM_IDX		(FAST_STORAGE_IDX_OFFSET+2)		// T
#define FAST_STORAGE_GET_ITEM_IDX		(FAST_STORAGE_IDX_OFFSET+3)		// U
#define FAST_STORAGE_REMOVE_ITEM_IDX	(FAST_STORAGE_IDX_OFFSET+4)		// V
#define FAST_STORAGE_STORE_IDX			(FAST_STORAGE_IDX_OFFSET+5)		// W
#define FAST_STORAGE_LOAD_IDX			(FAST_STORAGE_IDX_OFFSET+6)		// X

// format R <storage idx> <secret> <salt> 
// note: if storage idx >= FAST_STORAGE_MAX_STORAGES, the storage pointer will be NULL
int32_t fastNewStorage(const char *str) {
	int32_t idx=0;
	char secret[FAST_FULL_SECRET_LEN+1], *secretPtr=NULL;
	char salt[MAX_STR_LEN+1], *saltPtr=NULL;
	char *tmpStr=NULL, idxStr[MAX_STR_LEN+1];
	SecureStorageS *storage=NULL;

	setFastStr(idxStr, &tmpStr, str, 0, FAST_ONE_DIGIT_LEN, false);
	setFastSecretStr(secret, &secretPtr, str, FAST_ONE_DIGIT_LEN, FAST_SECRET_LEN);
	setFastStr(salt, &saltPtr, str, FAST_ONE_DIGIT_LEN+FAST_SECRET_LEN, FAST_USER_NAME_LEN, true);
	idx = idxStr[0] - '0';
	if (idx >= 0 && idx < FAST_STORAGE_MAX_STORAGES) {
		storage = &(internalStorage[idx]);
	}else
		storage = NULL;
	if (Debug)
		printf("fastNewStorage with the following parameters: idx %d (storage isNull? %d) secret '%s', salt '%s'\n", idx, storage == NULL, secretPtr, saltPtr);
	if (SecureStorage_NewStorage((unsigned char *)secretPtr, (unsigned char *)saltPtr, storage) == false) {
		return false;
	}
	storageWasInit[idx] = true;
	return true;
}

// format S <stoorage idx>
int32_t fastFreeStorage(const char *str) {
	int32_t idx=0;
	char *tmpStr=NULL, idxStr[MAX_STR_LEN+1];
	SecureStorageS *storage=NULL;

	setFastStr(idxStr, &tmpStr, str, 0, FAST_ONE_DIGIT_LEN, false);
	idx = idxStr[0] - '0';
	if (idx >= 0 && idx < FAST_STORAGE_MAX_STORAGES && storageWasInit[idx] == true) {
		storage = &(internalStorage[idx]);
		storageWasInit[idx] = false;
	}else
		storage = NULL;
	if (Debug)
		printf("fastFreeStorage with the following parameters: storage idx %d isNull %d\n", idx, storage == NULL);
	SecureStorage_FreeStorage(storage);
	return true;
}

// format T/U/V <storage idx> <key> <val> 
// note: if storage idx >= FAST_STORAGE_MAX_STORAGES, the storage pointer will be NULL
// I'm not checking full storage limits, the storage can't be full it the current system of values 1,2,4...512
int32_t fastHandleItem(const char *str, int32_t callIdx) {
	int32_t idx=0, keyLen=0, valLen=0;
	char key[FAST_FULL_SECRET_LEN+1], *keyPtr=NULL;
	char val[MAX_STR_LEN+1], *valPtr=NULL;
	char *tmpStr=NULL, idxStr[MAX_STR_LEN+1];
	SecureStorageS *storage=NULL;

	setFastStr(idxStr, &tmpStr, str, 0, FAST_ONE_DIGIT_LEN, false);
	setFastStr(key, &keyPtr, str, FAST_ONE_DIGIT_LEN, FAST_USER_NAME_LEN, true);
	setFastStr(val, &valPtr, str, FAST_ONE_DIGIT_LEN+FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	idx = idxStr[0] - '0';
	if (idx >= 0 && idx < FAST_STORAGE_MAX_STORAGES && storageWasInit[idx] == true) {
		storage = &(internalStorage[idx]);
	}else
		storage = NULL;
	if (Debug)
		printf("fastHandleItem func idx %c with the following parameters: idx %d (storage isNull? %d) key '%s', val '%s'\n", callIdx, idx, storage == NULL, keyPtr, valPtr);
	keyLen = 1; // the NULL must be found not by the keyLen
	if (keyPtr != NULL)
		keyLen = strlen(keyPtr);
	valLen = 1; // the NULL must be found not by the valLen
	if (valPtr != NULL)
		valLen = strlen(valPtr);
	switch (callIdx) {
		case FAST_STORAGE_ADD_ITEM_IDX:
			SecureStorage_AddItem(storage, (unsigned char *)keyPtr, keyLen, (unsigned char *)valPtr, valLen);
			break;
		case FAST_STORAGE_GET_ITEM_IDX:
			if (SecureStorage_GetItem(storage, (unsigned char *)keyPtr, keyLen, (unsigned char **)(&valPtr)) == true)
				Utils_Free(valPtr);
			break;
		case FAST_STORAGE_REMOVE_ITEM_IDX:
			SecureStorage_RemoveItem(storage, (unsigned char *)keyPtr, keyLen);
			break;
		default:
			printf("Internal error in fastHandleItem: unknown callIdx %d %c\n", callIdx, callIdx);
			exit(-1);
	}
	return true;
}

// format W/X <storage idx> <file name> <secret> <salt>
// note: if storage idx >= FAST_STORAGE_MAX_STORAGES, the storage pointer will be NULL
int32_t fastStorageStoreLoad(const char *str, int32_t callIdx) {
	int32_t idx=0;
	char secret[FAST_FULL_SECRET_LEN+1], *secretPtr=NULL;
	char salt[MAX_STR_LEN+1], *saltPtr=NULL;
	char fileName[MAX_STR_LEN+1], *fileNamePtr=NULL;
	char *tmpStr=NULL, idxStr[MAX_STR_LEN+1];
	char filePath[MAX_STR_LEN+1], *filePathPtr=NULL;
	SecureStorageS *storage=NULL;

	setFastStr(idxStr, &tmpStr, str, 0, FAST_ONE_DIGIT_LEN, false);
	setFastSecretStr(secret, &secretPtr, str, FAST_ONE_DIGIT_LEN, FAST_SECRET_LEN);
	setFastStr(salt, &saltPtr, str, FAST_ONE_DIGIT_LEN+FAST_SECRET_LEN, FAST_USER_NAME_LEN, true);
	setFastStr(fileName, &fileNamePtr, str, FAST_ONE_DIGIT_LEN+FAST_SECRET_LEN+FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, false);
	idx = idxStr[0] - '0';
	if (idx >= 0 && idx < FAST_STORAGE_MAX_STORAGES && storageWasInit[idx] == true) {
		storage = &(internalStorage[idx]);
	}else
		storage = NULL;
	if (fileNamePtr != NULL) {
		snprintf(filePath, MAX_STR_LEN, "%s/%s", TMP_FILE_DIR, fileNamePtr);
		filePathPtr = filePath;
	}else
		filePathPtr = NULL;
	if (Debug)
		printf("fastStoreLoad func idx %c with the following parameters: idx %d (storage isNull? %d) secret '%s', salt '%s', file name '%s'\n", callIdx, idx, storage == NULL, secretPtr, saltPtr, filePathPtr);
	switch (callIdx) {
		case FAST_STORAGE_STORE_IDX:
			SecureStorage_StoreSecureStorageToFile(filePathPtr, storage);
		case FAST_STORAGE_LOAD_IDX:
			SecureStorage_LoadSecureStorageFromFile(filePathPtr, (unsigned char *)secretPtr, (unsigned char *)saltPtr, storage);
			break;
		default:
			printf("Internal error in fastStoreLoad: unknown callIdx %d %c\n", callIdx, callIdx);
			exit(-1);
	}
	return true;
}

int32_t fastTestStorage(const char *callStr, const char *fileName, int32_t line, char *str) {
	int32_t found = false;
	int32_t callIdx = callStr[0];
	char *dataPtr=NULL;

	if (getParams("fastTestStorage", fileName, line, str, NUM_OF_FAST_PARAMS) == false)
		return false;
	if (Params[0] != NULL && strlen(Params[0])>1)
		dataPtr = &(Params[0][1]);
	switch (callIdx) {
		case FAST_STORAGE_NEW_IDX:
			fastNewStorage(dataPtr);
			found = true;
			break;
		case FAST_STORAGE_FREE_IDX:
			fastFreeStorage(dataPtr);
			found = true;
			break;
		case FAST_STORAGE_ADD_ITEM_IDX:
		case FAST_STORAGE_GET_ITEM_IDX:
		case FAST_STORAGE_REMOVE_ITEM_IDX:
			fastHandleItem(dataPtr, callIdx);
			found = true;
			break;
		case FAST_STORAGE_STORE_IDX:
		case FAST_STORAGE_LOAD_IDX:
			fastStorageStoreLoad(dataPtr, callIdx);
			found = true;
			break;
	}
	return found;
}