#include "parser_int.h"

#define FAST_USER_NEW_USER_IDX 					(FAST_USER_IDX_OFFSET+0) // a
#define FAST_USER_FREE_USER_IDX					(FAST_USER_IDX_OFFSET+1) // b
#define FAST_USER_NEW_GROUP_IDX 				(FAST_USER_IDX_OFFSET+2) // c
#define FAST_USER_FREE_GROUP_IDX				(FAST_USER_IDX_OFFSET+3) // d
#define FAST_USER_NEW_RESOURCE_IDX 				(FAST_USER_IDX_OFFSET+4) // e
#define FAST_USER_FREE_RESOURCE_IDX				(FAST_USER_IDX_OFFSET+5) // f

#define FAST_USER_ADD_USER_TO_GROUP_IDX 		(FAST_USER_IDX_OFFSET+6) // g
#define FAST_USER_REMOVE_USER_FROM_GROUP_IDX 	(FAST_USER_IDX_OFFSET+7) // h
#define FAST_USER_IS_USER_PART_OF_GROUP_IDX 	(FAST_USER_IDX_OFFSET+8) // i
#define FAST_USER_IS_EQUAL_IDX 					(FAST_USER_IDX_OFFSET+9) // j
#define FAST_USER_FREE_IDX 						(FAST_USER_IDX_OFFSET+10) // k
// don't use #define FAST_USER_FREE_ALL_IDX 					(FAST_USER_IDX_OFFSET+11) // l

#define FAST_USER_STORE_IDX	 					(FAST_USER_IDX_OFFSET+12) // m
#define FAST_USER_LOAD_IDX	 					(FAST_USER_IDX_OFFSET+13) // n

#define FAST_ENTITY_IN_LIST_IDX	 				(FAST_USER_IDX_OFFSET+14) // o
#define FAST_ENTITY_IN_USERS_LIST_IDX	 		(FAST_USER_IDX_OFFSET+15) // p
#define FAST_ENTITY_IN_GROUPS_LIST_IDX	 		(FAST_USER_IDX_OFFSET+16) // q
#define FAST_ENTITY_IN_RESOURCES_LIST_IDX 		(FAST_USER_IDX_OFFSET+17) // r

int32_t setFastStr(char *str, char **ptr, const char *data, int32_t start, int32_t maxLen, int32_t strechStr) {
	int32_t i=0, len=-1, strLen=-1;
	char ch=0;

	if (data == NULL) {
		len = 0;
	}else  {
		len = strlen(data) - start;
		if (len < 0)
			len = 0;
		if (len > maxLen)
			len = maxLen;
		memcpy(str, &(data[start]), len);
	}
	if (len >0)
		ch = str[0];
	else
		ch = 'a';
	if (strechStr == true) {
		strLen = pow(2.0, (ch % LOG_MAX_STR_LEN)); // between 1 and 512
		// printf("ch %d, ch modulu %d, strLen %d\n", ch, ch % LOG_MAX_STR_LEN, strLen);
		for (i=len ; i<strLen ; i++)
			str[i] = (ch + i);
		str[strLen] = 0;
	}else
		str[len] = 0;
	for (i=0 ; i<len ; i++) {
		if (str[i] == TEST_NULL_CHAR)
			str[i] = 0;
	}
	if (str[0] == 0)
		*ptr = NULL;
	else
		*ptr = str;
	return true;
}

// read fast str and duplicate it into full secret string, to limit the AFL num of parameters to play with
int32_t setFastSecretStr(char *str, char **ptr, const char *data, int32_t start, int32_t maxLen) {
	int32_t idx=FAST_SECRET_LEN;

	setFastStr(str, ptr, data, start, maxLen, false);
	while (idx<FAST_FULL_SECRET_LEN) {
		str[idx] = str[idx-FAST_SECRET_LEN];
		idx++;
	}
	str[FAST_FULL_SECRET_LEN] = 0;
	return true;
}

// int32_t EntityManager_AddUser(EntityManager *entityManager, const char *name);
// format a <user name>
int32_t fastCreateNewUser(const char *str) {
	char name[MAX_STR_LEN+1], *namePtr=NULL;
	
	setFastStr(name, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("Create user with the following parameters: user name '%s'\n", namePtr);
	EntityManager_AddUser(EntityListData, namePtr);
	return true;
}

// void EntityManager_RemoveUser(EntityManager *entityManager, const char *name);
// format b <user name>
int32_t fastFreeUser(const char *str) {
	char name[MAX_STR_LEN+1], *namePtr=NULL;

	setFastStr(name, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("Free user with the following parameters: user name '%s'\n", namePtr);
	EntityManager_RemoveUser(EntityListData, namePtr);
	return true;
}

// int32_t EntityManager_AddGroup(EntityManager *entityManager, const char *name);
// format c <name>
int32_t fastCreateNewGroup(const char *str) {
	char name[MAX_STR_LEN+1], *namePtr=NULL;
	
	setFastStr(name, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("Create group with the following parameters: name '%s'\n", namePtr);
	EntityManager_AddGroup(EntityListData, namePtr);
	return true;
}

// void EntityManager_RemoveGroup(EntityManager *entityManager, const char *name);
// format d <name>
int32_t fastFreeGroup(const char *str) {
	char name[MAX_STR_LEN+1], *namePtr=NULL;

	setFastStr(name, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("Free group with the following parameters: name '%s'\n", namePtr);
	EntityManager_RemoveGroup(EntityListData, namePtr);
	return true;
}

// int32_t EntityManager_AddResource(EntityManager *entityManager, const char *name);
// format e <name>
int32_t fastCreateNewResource(const char *str) {
	char name[MAX_STR_LEN+1], *namePtr=NULL;
	
	setFastStr(name, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("Create resource with the following parameters: name '%s'\n", namePtr);
	EntityManager_AddResource(EntityListData, namePtr);
	return true;
}

// void EntityManager_RemoveResource(EntityManager *entityManager, const char *name);
// format f <user name>
int32_t fastFreeResource(const char *str) {
	char name[MAX_STR_LEN+1], *namePtr=NULL;

	setFastStr(name, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("Free resource with the following parameters: name '%s'\n", namePtr);
	EntityManager_RemoveResource(EntityListData, namePtr);
	return true;
}

// int32_t EntityManager_AddUserToGroup(EntityManager *entityManager, const char *groupName, const char *userName);
// int32_t EntityManager_RemoveUserFromGroup(EntityManager *entityManager, const char *groupName, const char *userName);
// int32_t EntityManager_IsUserPartOfAGroup(const EntityManager *entityManager, const char *groupName, const char *userName);
// format g/h/i <group name> <user name>
int32_t fastUserInGroup(const char *str, int32_t type) {
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char groupName[MAX_STR_LEN+1], *groupNamePtr=NULL;

	setFastStr(groupName, &groupNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(userName, &userNamePtr, str, FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastAddRemoveUserToGroup add/remove %d with the following parameters: group name '%s' user name '%s'\n", type, groupNamePtr, userNamePtr);
	if (type == FAST_USER_ADD_USER_TO_GROUP_IDX)
		return EntityManager_AddUserToGroup(EntityListData, groupNamePtr, userNamePtr);
	else if (type == FAST_USER_REMOVE_USER_FROM_GROUP_IDX)
		return EntityManager_RemoveUserFromGroup(EntityListData, groupNamePtr, userNamePtr);
	return EntityManager_IsUserPartOfAGroup(EntityListData, groupNamePtr, userNamePtr);
}

// int32_t EntityManagerTest_IsEqual(const EntityManager *entityManager1, const EntityManager *entityManager2);
// format j idx1, idx2 
// note: if idx is odd then its the entityManager else its NULL
int32_t fastIsEqual(const char *str) {
	int32_t i, idx=0;
	char *tmpStr=NULL, idxStr[MAX_STR_LEN+1];
	EntityManager *entityManager[2];

	for (i=0 ; i<2 ; i++) {
		setFastStr(idxStr, &tmpStr, str, FAST_ONE_DIGIT_LEN*i, FAST_ONE_DIGIT_LEN, false);
		idx = idxStr[0] % 2;
		if (idx != 0)
			entityManager[i] = EntityListData;
		else 
			entityManager[i] = NULL;
	}
	if (Debug)
		printf("fastIsEqual with the following parameters: entityManager1 isNull? %d entityManager2 isNull? %d\n", entityManager[0] == NULL, entityManager[1] == NULL);
	return EntityManager_IsEqual(entityManager[0], entityManager[1]);
}

// void EntityManager_Free(EntityManager *entityManager, const char *name);
// format k <name>
int32_t fastFreeEntity(const char *str) {
	char name[MAX_STR_LEN+1], *namePtr=NULL;

	setFastStr(name, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastFreeEntity with the following parameters: name '%s'\n", namePtr);
	EntityManager_Free(EntityListData, namePtr);
	return true;
}

/* don't use it if for clear memory
// void EntityManager_FreeAll(EntityManager *entityManager);
// format l idx
int32_t fastFreeAll(const char *str) {
	int32_t idx=0;
	char *tmpStr=NULL, idxStr[MAX_STR_LEN+1];
	EntityManager *entityManager;

	setFastStr(idxStr, &tmpStr, str, 0, FAST_ONE_DIGIT_LEN, false);
	idx = idxStr[0] % 2;
	if (idx != 0)
		entityManager = EntityListData;
	else 
		entityManager = NULL;
	if (Debug)
		printf("fastFreeAll with the following parameters: entityManager is null ? %d\n", entityManager == NULL);
	EntityManager_FreeAll(entityManager);
	return true;
}
*/

// format o/p/q/r idx1 <user name>
// note: if idx is odd then its the entityManager else its NULL
int32_t fastIsEntityInList(const char *str, int32_t type) {
	int32_t i, idx=0;
	char *tmpStr=NULL, idxStr[MAX_STR_LEN+1];
	char name[MAX_STR_LEN+1], *namePtr=NULL;
	EntityManager *entityManager;
	
	setFastStr(idxStr, &tmpStr, str, 0, FAST_ONE_DIGIT_LEN, false);
	setFastStr(name, &namePtr, str, FAST_ONE_DIGIT_LEN, FAST_USER_NAME_LEN, true);
	idx = idxStr[0] % 2;
	if (idx != 0)
		entityManager = EntityListData;
	else 
		entityManager = NULL;
	if (Debug)
		printf("IsEntityInList with the following parameters: entityManager1 isNull? %d user name '%s'\n", entityManager == NULL, namePtr);
	if (type == FAST_ENTITY_IN_LIST_IDX)
		return EntityManager_IsEntityInList(entityManager, namePtr);
	else if (type == FAST_ENTITY_IN_USERS_LIST_IDX)
		return EntityManager_IsEntityInUsersList(entityManager, namePtr);
	if (type == FAST_ENTITY_IN_GROUPS_LIST_IDX)
		return EntityManager_IsEntityInGroupsList(entityManager, namePtr);
	return EntityManager_IsEntityInResourcesList(entityManager, namePtr);
}

// int32_t EntityManager_Store(const EntityManager *entityManager, const char *fileName, const unsigned char *secret);
// format m/n <storage id> <prefix> 
// note: storage idx: 0 = no storage, only 2 storages, if id > 2, i will use it as 1
int32_t fastStoreLoad(int32_t idx, const char *str) {
	int32_t type=-1, storageIdx=0;
	char *tmpStr=NULL, *prefixPtr=NULL;
	char prefix[MAX_STR_LEN+1], storageStr[MAX_STR_LEN+1];
	EntityManager *entityManager;

	type = STORE_IDX;
	if (idx == FAST_USER_LOAD_IDX)
		type = LOAD_IDX;
	setFastStr(storageStr, &tmpStr, str, 0, FAST_ONE_DIGIT_LEN, false);
	setFastStr(prefix, &prefixPtr, str, FAST_ONE_DIGIT_LEN, FAST_PREFIX_LEN, true);
	storageIdx = storageStr[0] % MAX_NUM_OF_STORAGES;
	if (storageIdx > 0)
		entityManager = EntityListData;
	else 
		entityManager = NULL;
	printf("%s user with the following parameters: storage idx %d, prefix '%s'\n", StoreLoadStr[type], storageIdx, prefixPtr);
	if (type == STORE_IDX) {
		EntityManager_Store(entityManager, FILE_NAME, SECRET, SALT);
	}else {
		EntityManager_Load(&entityManager, FILE_NAME, SECRET, SALT);
	}
	return true;
}

int32_t fastTestUser(const char *callStr, const char *fileName, int32_t line, char *str) {
	int32_t found = false;
	int32_t callIdx = callStr[0];
	char *dataPtr=NULL;

	if (getParams("fastTestUser", fileName, line, str, NUM_OF_FAST_PARAMS) == false)
		return false;
	if (Params[0] != NULL && strlen(Params[0])>1)
		dataPtr = &(Params[0][1]);
	switch (callIdx) {
		case FAST_USER_NEW_USER_IDX:
			fastCreateNewUser(dataPtr);
			found = true;
			break;
		case FAST_USER_FREE_USER_IDX:
			fastFreeUser(dataPtr);
			found = true;
			break;
		case FAST_USER_NEW_GROUP_IDX:
			fastCreateNewGroup(dataPtr);
			found = true;
			break;
		case FAST_USER_FREE_GROUP_IDX:
			fastFreeGroup(dataPtr);
			found = true;
			break;
		case FAST_USER_NEW_RESOURCE_IDX:
			fastCreateNewResource(dataPtr);
			found = true;
			break;
		case FAST_USER_FREE_RESOURCE_IDX:
			fastFreeResource(dataPtr);
			found = true;
			break;
		case FAST_USER_ADD_USER_TO_GROUP_IDX:
		case FAST_USER_REMOVE_USER_FROM_GROUP_IDX:
		case FAST_USER_IS_USER_PART_OF_GROUP_IDX:
			fastUserInGroup(dataPtr, callIdx);
			found = true;
			break;
		case FAST_USER_IS_EQUAL_IDX:
			fastIsEqual(dataPtr);
			found = true;
			break;
		case FAST_USER_FREE_IDX:
			fastFreeEntity(dataPtr);
			found = true;
			break;
		case FAST_USER_STORE_IDX:
		case FAST_USER_LOAD_IDX:
			fastStoreLoad(callIdx, dataPtr);
			found = true;
			break;
		case FAST_ENTITY_IN_LIST_IDX:
		case FAST_ENTITY_IN_USERS_LIST_IDX:
		case FAST_ENTITY_IN_GROUPS_LIST_IDX:
		case FAST_ENTITY_IN_RESOURCES_LIST_IDX:
			fastIsEntityInList(dataPtr, callIdx);
			found = true;
			break;
	}
	return found;
}