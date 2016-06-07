#include "parser_int.h"

#define FAST_AM_NEW_USER_IDX 		(FAST_AM_IDX_OFFSET+0)		// 1
#define FAST_AM_FREE_IDX 			(FAST_AM_IDX_OFFSET+1)		// 2
#define FAST_AM_UPDATE_PWD_IDX		(FAST_AM_IDX_OFFSET+2)		// 3
#define FAST_AM_SET_PRIVILEGE_IDX	(FAST_AM_IDX_OFFSET+3)		// 4
#define FAST_AM_VERIFY_PWD_IDX		(FAST_AM_IDX_OFFSET+4)		// 5
#define FAST_AM_IS_EQUAL_IDX		(FAST_AM_IDX_OFFSET+5)		// 6

char *PrivilegeVec[NUM_OF_PRIVILEGE+1]={NULL, SUPER_USER_PERMISSION_STR, USER_PERMISSION_STR, ADMIN_PERMISSION_STR};

// format 1 <username> <privilege> <pwd> <salt>
// int32_t Accounts_NewUser(AmUserInfoS **user, const char *privilege, const unsigned char *sPwd, const unsigned char *sSalt);
int32_t fastNewAmUser(const char *str) {
	int32_t privilegeIdx=-1;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char privilegeStr[FAST_ONE_DIGIT_LEN+1], *tmpPtr=NULL;
	char pwdStr[FAST_FULL_SECRET_LEN+1], *pwdPtr=NULL;
	char saltStr[MAX_STR_LEN+1], *saltPtr=NULL;
	AmUserInfoS *amUser=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(privilegeStr, &tmpPtr, str, FAST_USER_NAME_LEN, FAST_ONE_DIGIT_LEN, false);
	setFastSecretStr(pwdStr, &pwdPtr, str, FAST_USER_NAME_LEN+FAST_ONE_DIGIT_LEN, FAST_SECRET_LEN);
	setFastStr(saltStr, &saltPtr, str, FAST_USER_NAME_LEN+FAST_ONE_DIGIT_LEN+FAST_SECRET_LEN, FAST_SECRET_LEN, true);
	privilegeIdx = (privilegeStr[0] % (NUM_OF_PRIVILEGE+1)) && 0xf;
	if (Accounts_NewUser(&amUser, PrivilegeVec[privilegeIdx], (unsigned char*) pwdPtr, (unsigned char*) saltPtr) == false) {
		printf("Error while generating new AM user '%s', error: %s\n", userNamePtr, errStr);
		return false;
	}
	if (Debug)
		printf("fastNewAmUser with the following parameters: user name '%s', privilege '%s' pwd '%s', salt '%s'\n", userNamePtr, PrivilegeVec[privilegeIdx], pwdPtr, saltPtr);
	if (EntityManager_IsEntityInList(EntityListData, userNamePtr) == false)
		Accounts_FreeUser((void *)amUser);
	else {
		EntityManager_RemoveProperty(EntityListData, userNamePtr, AM_PROPERTY_NAME, true);
		EntityManager_RegisterProperty(EntityListData, userNamePtr, AM_PROPERTY_NAME, amUser);
	}
	return true;
}

// format 2 <user name>
int32_t fastFreeAmProperty(const char *str) {
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastFreeAmProperty with the following parameters: userName '%s'\n", userNamePtr);
	EntityManager_RemoveProperty(EntityListData, userNamePtr, AM_PROPERTY_NAME, true);
	return true;
}

// format 3 <username> <cPwd> <nPwd>
int32_t fastUpdateAmPwd(const char *str) {
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char cPwdStr[FAST_FULL_SECRET_LEN+1], *cPwdPtr=NULL;
	char nPwdStr[FAST_FULL_SECRET_LEN+1], *nPwdPtr=NULL;
	AmUserInfoS *amUser=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastSecretStr(cPwdStr, &cPwdPtr, str, FAST_USER_NAME_LEN, FAST_SECRET_LEN);
	setFastSecretStr(nPwdStr, &nPwdPtr, str, FAST_USER_NAME_LEN+FAST_SECRET_LEN, FAST_SECRET_LEN);
	if (Debug)
		printf("fastUpdateAmUser with the following parameters: user name '%s', cPwd '%s' nPWd '%s'\n", userNamePtr, cPwdPtr, nPwdPtr);
	if (EntityManager_GetProperty(EntityListData, userNamePtr,  AM_PROPERTY_NAME, (void **)&amUser) == true)
		return Accounts_UpdateUserPwd(amUser, userNamePtr, (unsigned char *)cPwdPtr, (unsigned char *)nPwdPtr);
	return false;
}

// format 4 <username> <privilege>
int32_t fastSetAmPrivilege(const char *str) {
	int32_t privilegeIdx=-1;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char privilegeStr[FAST_ONE_DIGIT_LEN+1], *tmpPtr=NULL;
	AmUserInfoS *amUser=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(privilegeStr, &tmpPtr, str, FAST_USER_NAME_LEN, FAST_ONE_DIGIT_LEN, false);
	if (tmpPtr != NULL)
		privilegeIdx = (privilegeStr[0] % (NUM_OF_PRIVILEGE+1)) & 0xf;
	else
		privilegeIdx = 0;
	if (Debug)
		printf("fastSetAmPrivilege with the following parameters: user name '%s', privilege '%s'\n", userNamePtr, PrivilegeVec[privilegeIdx]);
	EntityManager_GetProperty(EntityListData, userNamePtr,  AM_PROPERTY_NAME, (void **)&amUser);
	return Accounts_SetUserPrivilege(amUser, PrivilegeVec[privilegeIdx]);
}

// format 5 <username> <pwd>
int32_t fastVerifyAmPwd(const char *str) {
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char pwdStr[FAST_FULL_SECRET_LEN+1], *pwdPtr=NULL;
	AmUserInfoS *amUser=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastSecretStr(pwdStr, &pwdPtr, str, FAST_USER_NAME_LEN, FAST_SECRET_LEN);
	if (Debug)
		printf("fastVerifyAmUser with the following parameters: user name '%s', pwd '%s'\n", userNamePtr, pwdPtr);
	if (EntityManager_GetProperty(EntityListData, userNamePtr,  AM_PROPERTY_NAME, (void **)&amUser) == false)
		return false;
	return Accounts_VerifyPassword(amUser, (unsigned char *)pwdPtr);
}

// format 6 <username1> <username2>
int32_t fastIsEqualAmUsers(const char *str) {
	void *data1 = NULL, *data2 = NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr[2];

	setFastStr(userName, &userNamePtr[0], str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(userName, &userNamePtr[1], str, FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastIsEqualAmUsers with the following parameters: amUser1 '%s' amUser2 '%s'\n", userNamePtr[0], userNamePtr[1]);
	EntityManager_GetProperty(EntityListData, userNamePtr[0],  AM_PROPERTY_NAME, &data1);
	EntityManager_GetProperty(EntityListData, userNamePtr[1],  AM_PROPERTY_NAME, &data2);
	return Accounts_IsEqual(data1, data2);
}

int32_t fastTestAm(const char *callStr, const char *fileName, int32_t line, char *str) {
	int32_t found = false;
	int32_t callIdx = callStr[0];
	char *dataPtr=NULL;

	if (getParams("fastTestAm", fileName, line, str, NUM_OF_FAST_PARAMS) == false)
		return false;
	if (Params[0] != NULL && strlen(Params[0])>1)
		dataPtr = &(Params[0][1]);
	switch (callIdx) {
		case FAST_AM_NEW_USER_IDX:
			fastNewAmUser(dataPtr);
			found = true;
			break;
		case FAST_AM_FREE_IDX:
			fastFreeAmProperty(dataPtr);
			found = true;
			break;
		case FAST_AM_UPDATE_PWD_IDX:
			fastUpdateAmPwd(dataPtr);
			found = true;
			break;
		case FAST_AM_SET_PRIVILEGE_IDX:
			fastSetAmPrivilege(dataPtr);
			found = true;
			break;
		case FAST_AM_VERIFY_PWD_IDX:
			fastVerifyAmPwd(dataPtr);
			found = true;
			break;
		case FAST_AM_IS_EQUAL_IDX:
			fastIsEqualAmUsers(dataPtr);
			found = true;
			break;
	}
	return found;
}