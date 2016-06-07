#include "parser_int.h"

#define MAX_NUM_OF_ACLS 3

#define FAST_ACL_ENTRY_ADD_PERMISSION_IDX			(FAST_ACL_IDX_OFFSET+0)		// u
#define FAST_ACL_ENTRY_REMOVE_PERMISSION_IDX 		(FAST_ACL_IDX_OFFSET+1)		// v
#define FAST_ACL_ENTRY_EQUAL_IDX					(FAST_ACL_IDX_OFFSET+2)		// w
#define FAST_ACL_ENTRY_UPDATE_PERMISSION_IDX		(FAST_ACL_IDX_OFFSET+3)		// x
#define FAST_ACL_ADD_PERMISSION_IDX					(FAST_ACL_IDX_OFFSET+4)		// y
#define FAST_ACL_REMOVE_PERMISSION_IDX 				(FAST_ACL_IDX_OFFSET+5)		// z
#define FAST_ACL_CHECK_PERMISSION_IDX 				(FAST_ACL_IDX_OFFSET+6)		// {
#define FAST_ACL_WHO_USES_PERMISSION_IDX 			(FAST_ACL_IDX_OFFSET+7)		// | 
#define FAST_ACL_GET_ALL_PERMISSION_IDX 			(FAST_ACL_IDX_OFFSET+8)		// }

// format j/k <resource name> <entity name> <permission>
int32_t fastAddRemovePermissionToEntry(int32_t idx, const char *str) {
	char entityName[MAX_STR_LEN+1], *entityNamePtr=NULL;
	char resourceName[MAX_STR_LEN+1], *resourceNamePtr=NULL;
	char permission[MAX_STR_LEN+1], *permissionPtr=NULL;
	AclS *acl=NULL;

	setFastStr(resourceName, &resourceNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(entityName, &entityNamePtr, str, FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	setFastStr(permission, &permissionPtr, str, FAST_USER_NAME_LEN+FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	if (EntityManager_IsEntityInResourcesList(EntityListData, resourceName) == false)
		return false;
	if (EntityManager_GetProperty(EntityListData, resourceNamePtr, ACL_PROPERTY_NAME, (void **)&acl) == false) {
		Acl_New(&acl);
		EntityManager_RegisterProperty(EntityListData, resourceNamePtr, ACL_PROPERTY_NAME, acl);
	}
	if (idx == FAST_ACL_ENTRY_ADD_PERMISSION_IDX) {
		return Acl_AddPermissionToResource(EntityListData, resourceNamePtr, entityNamePtr, permission);
	}
	return Acl_RemovePermissionFromResource(EntityListData, resourceNamePtr, entityNamePtr, permission);
}

// format l/m <entityname1> <entityname2>
int32_t fastIsEqualUpdateAclEntries(int32_t idx, const char *str) {
	void *data1 = NULL, *data2 = NULL;
	char entityName[2][MAX_STR_LEN+1], *entityNamePtr[2]={NULL,NULL};

	setFastStr(entityName[0], &(entityNamePtr[0]), str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(entityName[1], &(entityNamePtr[1]), str, FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastIsEqualUpdateAclEntries with the following parameters: entity name 0 '%s' entity name 1 '%s'\n", entityNamePtr[0], entityNamePtr[1]);
	if (idx == FAST_ACL_ENTRY_EQUAL_IDX)
		return Acl_IsEqual(data1, data2);
	else if (data1 != NULL && data2 != NULL) {
		// not relevant return updateEntryPermissions((AclPermissionsS *) data1->, (AclPermissionsS **) &data2);
		return 0;
	}
}

// format n/o/p/q/r <resource name> <entity name> <permission>
int32_t fastHandlePermission(int32_t idx, const char *str) {
	int32_t funcIdx = -1, ret = false;
	char name[MAX_STR_LEN+1], *namePtr=NULL;
	char resourceName[MAX_STR_LEN+1], *resourceNamePtr=NULL;
	char permission[MAX_STR_LEN+1], *permissionPtr=NULL;
	char *entryName = "testfastAcl";
	char *funcName[] = {"Undefined", "addPermissionToEntry", "removePermissionFromEntry", "checkPermission", "WhoUsesAPermission", "GetAllPermissions"};
	htab *whoList=NULL;
	AclPermissionsS *entry;
	AclS *acl=NULL;

	setFastStr(resourceName, &resourceNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(name, &namePtr, str, FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	setFastStr(permission, &permissionPtr, str, FAST_USER_NAME_LEN+FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	funcIdx = idx - FAST_ACL_ADD_PERMISSION_IDX + 1;
	if (funcIdx<1 || funcIdx > sizeof(funcName) / sizeof(char *)) {
		funcIdx = 0;
		printf("Error in fastHandlePermission: idx %d (%d) is not OK, len %ld\n", idx, funcIdx, sizeof(funcName) / sizeof(char *));
	}
	if (Debug)
		printf("fastHandlePermission with the following parameters: call func '%s': name '%s' permission '%s'\n", funcName[funcIdx], namePtr, permissionPtr);
	if (EntityManager_IsEntityInResourcesList(EntityListData, resourceName) == false)
		return false;
	if (EntityManager_GetProperty(EntityListData, resourceNamePtr, ACL_PROPERTY_NAME, (void **)&acl) == false) {
		Acl_New(&acl);
		EntityManager_RegisterProperty(EntityListData, resourceNamePtr, ACL_PROPERTY_NAME, acl);
	}
	if (idx == FAST_ACL_CHECK_PERMISSION_IDX)
		return Acl_CheckEntityPermission(EntityListData, resourceNamePtr, namePtr, permissionPtr);
	else if (idx == FAST_ACL_ADD_PERMISSION_IDX) {
		return Acl_AddPermissionToResource(EntityListData, resourceNamePtr, namePtr, permissionPtr);
	}else if (idx == FAST_ACL_REMOVE_PERMISSION_IDX) {
		return Acl_RemovePermissionFromResource(EntityListData, resourceNamePtr, namePtr, permissionPtr);
	}else if (idx == FAST_ACL_WHO_USES_PERMISSION_IDX) {
		whoList = hcreate(8);
		ret = Acl_WhoUseAPermission(EntityListData, permissionPtr, whoList);
		hdestroy(whoList);
		return ret;
	}else{ // idx == FAST_ACL_GET_ALL_PERMISSION_IDX
		// fix it addEntry(acl, entryName, &entry);
		//ret = Acl_GetAllPermissions(EntityListData, resourceNamePtr, entry);
		//Acl_RemoveEntry(entry, entryName);
		// return ret;
		return true;
	}
}

int32_t fastTestAcl(const char *callStr, const char *fileName, int32_t line, char *str) {
	int32_t found = false;
	int32_t callIdx = callStr[0];
	char *dataPtr=NULL;

	if (getParams("fastTestAcl", fileName, line, str, NUM_OF_FAST_PARAMS) == false)
		return false;
	if (Params[0] != NULL && strlen(Params[0])>1)
		dataPtr = &(Params[0][1]);
	switch (callIdx) {
		case FAST_ACL_ENTRY_ADD_PERMISSION_IDX:
		case FAST_ACL_ENTRY_REMOVE_PERMISSION_IDX:
			fastAddRemovePermissionToEntry(callIdx, dataPtr);
			found = true;
			break;
		case FAST_ACL_ENTRY_EQUAL_IDX:
		case FAST_ACL_ENTRY_UPDATE_PERMISSION_IDX:
			fastIsEqualUpdateAclEntries(callIdx, dataPtr);
			found = true;
			break;
		case FAST_ACL_CHECK_PERMISSION_IDX:
		case FAST_ACL_REMOVE_PERMISSION_IDX:
		case FAST_ACL_ADD_PERMISSION_IDX:
		case FAST_ACL_WHO_USES_PERMISSION_IDX:
		case FAST_ACL_GET_ALL_PERMISSION_IDX:
			fastHandlePermission(callIdx, dataPtr);
			found = true;
			break;
	}
	return found;
}