#include "parser_int.h"

#define FAST_PWD_NEW_PWD_IDX 		(FAST_PWD_IDX_OFFSET+0)		// #
#define FAST_PWD_FREE_IDX 			(FAST_PWD_IDX_OFFSET+1)		// $
#define FAST_PWD_UPDATE_PWD_IDX		(FAST_PWD_IDX_OFFSET+2)		// %
#define FAST_PWD_SET_TEMPORARY_IDX	(FAST_PWD_IDX_OFFSET+3)		// &
#define FAST_PWD_VERIFY_PWD_IDX		(FAST_PWD_IDX_OFFSET+4)		// '
#define FAST_PWD_IS_EQUAL_IDX		(FAST_PWD_IDX_OFFSET+5)		// (
#define FAST_PWD_GENERATEL_IDX		(FAST_PWD_IDX_OFFSET+6)		// )
#define FAST_PWD_IS_VALID_IDX		(FAST_PWD_IDX_OFFSET+7)		// *

// format #  <userName> <pwd> <salt>
// bool Pwd_NewUserPwd(PwdS **newPwd, const unsigned char *sPwd, const unsigned char *sSalt);
int32_t fastNewPwdUser(const char *str) {
	char pwdStr[FAST_FULL_SECRET_LEN+1], *pwdPtr=NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char saltStr[MAX_STR_LEN+1], *saltPtr=NULL;
	PwdS *pwdUser=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastSecretStr(pwdStr, &pwdPtr, str, FAST_USER_NAME_LEN, FAST_SECRET_LEN);
	setFastStr(saltStr, &saltPtr, str, FAST_USER_NAME_LEN+FAST_SECRET_LEN, FAST_SECRET_LEN, true);
	if (Pwd_NewUserPwd(&pwdUser, (unsigned char*)pwdPtr, (unsigned char*)saltPtr) == false) {
		return false;
	}
	if (Debug)
		printf("fastNewPwdUser with the following parameters: userName '%s', pwd '%s', salt '%s'\n", userNamePtr, pwdPtr, saltPtr);
	if (EntityManager_IsEntityInList(EntityListData, userNamePtr) == false)
		Pwd_FreeUserPwd((void *)pwdUser);
	else {
		EntityManager_RemoveProperty(EntityListData, userNamePtr, PWD_PROPERTY_NAME, true);
		EntityManager_RegisterProperty(EntityListData, userNamePtr, PWD_PROPERTY_NAME, pwdUser);
	}
	return true;
}

// format $ <user name>
int32_t fastFreePwdProperty(const char *str) {
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastFreePwdProperty with the following parameters: userName '%s'\n", userNamePtr);
	EntityManager_RemoveProperty(EntityListData, userNamePtr, PWD_PROPERTY_NAME, true);
	return true;
}

// format % <username> <cPwd> <nPwd>
int32_t fastUpdatePwd(const char *str) {
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char cPwdStr[FAST_FULL_SECRET_LEN+1], *cPwdPtr=NULL;
	char nPwdStr[FAST_FULL_SECRET_LEN+1], *nPwdPtr=NULL;
	PwdS *pwdUser=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastSecretStr(cPwdStr, &cPwdPtr, str, FAST_USER_NAME_LEN, FAST_SECRET_LEN);
	setFastSecretStr(nPwdStr, &nPwdPtr, str, FAST_USER_NAME_LEN+FAST_SECRET_LEN, FAST_SECRET_LEN);
	if (Debug)
		printf("fastUpdatePwdUser with the following parameters: user name '%s', cPwd '%s' nPWd '%s'\n", userNamePtr, cPwdPtr, nPwdPtr);
	if (EntityManager_GetProperty(EntityListData, userNamePtr,  PWD_PROPERTY_NAME, (void **)&pwdUser) == true)
		return Pwd_UpdatePassword(pwdUser, (unsigned char *)cPwdPtr, (unsigned char *)nPwdPtr);
	return false;
}

// format & <username> <idx>
int32_t fastSetTemporary(const char *str) {
	bool flag=false;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char *tmpStr=NULL, idxStr[MAX_STR_LEN+1];
	PwdS *pwdUser=NULL;
	
	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(idxStr, &tmpStr, str, FAST_USER_NAME_LEN, FAST_ONE_DIGIT_LEN, false);
	flag = (idxStr[0] % 2 == 0);
	if (Debug)
		printf("fastSetTemporary with the following parameters: user name '%s', flag %d\n", userNamePtr, (int)flag);
	EntityManager_GetProperty(EntityListData, userNamePtr,  PWD_PROPERTY_NAME, (void **)&pwdUser);
	Pwd_SetTemporaryPwd(pwdUser, flag);
	return true;
}

// format ' <username> <pwd>
int32_t fastVerifyPwd(const char *str) {
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char pwdStr[FAST_FULL_SECRET_LEN+1], *pwdPtr=NULL;
	PwdS *pwdUser=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastSecretStr(pwdStr, &pwdPtr, str, FAST_USER_NAME_LEN, FAST_SECRET_LEN);
	if (Debug)
		printf("fastVerifyPwd with the following parameters: user name '%s', pwd '%s'\n", userNamePtr, pwdPtr);
	if (EntityManager_GetProperty(EntityListData, userNamePtr,  PWD_PROPERTY_NAME, (void **)&pwdUser) == false)
		return false;
	return Pwd_VerifyPassword(pwdUser, (unsigned char *)pwdPtr);
}

// format ( <username1> <username2>
int32_t fastIsEqualPwdUsers(const char *str) {
	void *data1 = NULL, *data2 = NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr[2];

	setFastStr(userName, &userNamePtr[0], str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(userName, &userNamePtr[1], str, FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastIsEqualPwdUsers with the following parameters: pwdUser1 '%s' pwdUser2 '%s'\n", userNamePtr[0], userNamePtr[1]);
	EntityManager_GetProperty(EntityListData, userNamePtr[0],  PWD_PROPERTY_NAME, &data1);
	EntityManager_GetProperty(EntityListData, userNamePtr[1],  PWD_PROPERTY_NAME, &data2);
	return Pwd_IsEqual(data1, data2);
}

// format ) <idx>
int32_t fastGeneratePwd(const char *str) {
	int32_t len=0;
	char *tmpPtr=NULL;
	unsigned char *tmp=NULL;
	char lenStr[MAX_STR_LEN+1];
	
	setFastStr(lenStr, &tmpPtr, str, 0, FAST_TWO_DIGITS_LEN, false);
	if (tmpPtr != NULL && strlen(lenStr) >= 2)
		len = lenStr[0] * 256 + lenStr[1];
	else
		len = -1;
	if (Debug)
		printf("fastGeneratePwd with the following parameters: len %d\n", len);
	Utils_GenerateNewValidPassword(&tmp, len);
	Utils_Free(tmp);
	return true;
}

// format * <pwd>
int32_t fastIsPwdValid(const char *str) {
	char userName[MAX_STR_LEN+1], *userNamePtr;
	char pwdStr[FAST_FULL_SECRET_LEN+1], *pwdPtr=NULL;
	PwdS *pwdUser=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastSecretStr(pwdStr, &pwdPtr, str, FAST_USER_NAME_LEN, FAST_SECRET_LEN);
	if (Debug)
		printf("fastIsPwdValid with the following parameters: user name '%s', pwd '%s'\n", userNamePtr, pwdPtr);
	EntityManager_GetProperty(EntityListData, userNamePtr, PWD_PROPERTY_NAME, (void **)&pwdUser);
	return Pwd_IsPwdValid(pwdUser, (unsigned char *)pwdPtr);
}

int32_t fastTestPwd(const char *callStr, const char *fileName, int32_t line, char *str) {
	int32_t found = false;
	int32_t callIdx = callStr[0];
	char *dataPtr=NULL;

	if (getParams("fastTestPwd", fileName, line, str, NUM_OF_FAST_PARAMS) == false)
		return false;
	if (Params[0] != NULL && strlen(Params[0])>1)
		dataPtr = &(Params[0][1]);
	switch (callIdx) {
		case FAST_PWD_NEW_PWD_IDX:
			fastNewPwdUser(dataPtr);
			found = true;
			break;
		case FAST_PWD_FREE_IDX:
			fastFreePwdProperty(dataPtr);
			found = true;
			break;
		case FAST_PWD_UPDATE_PWD_IDX:
			fastUpdatePwd(dataPtr);
			found = true;
			break;
		case FAST_PWD_SET_TEMPORARY_IDX:
			fastSetTemporary(dataPtr);
			found = true;
			break;
		case FAST_PWD_VERIFY_PWD_IDX:
			fastVerifyPwd(dataPtr);
			found = true;
			break;
		case FAST_PWD_IS_EQUAL_IDX:
			fastIsEqualPwdUsers(dataPtr);
			found = true;
			break;
		case FAST_PWD_GENERATEL_IDX:
			fastGeneratePwd(dataPtr);
			found = true;
			break;
		case FAST_PWD_IS_VALID_IDX:
			fastIsPwdValid(dataPtr);
			found = true;
			break;
	}
	return found;
}