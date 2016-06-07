#include "parser_int.h"

#define FAST_OTPUSER_NEW_USER_IDX 			(FAST_OTP_IDX_OFFSET+9)		// J
#define FAST_OTPUSER_FREE_IDX 				(FAST_OTP_IDX_OFFSET+10)	// K
#define FAST_OTPUSER_SET_BLOCK_STATE_IDX 	(FAST_OTP_IDX_OFFSET+11)	// L
#define FAST_OTPUSER_CAN_CHECK_CODE_IDX 	(FAST_OTP_IDX_OFFSET+12)	// M
#define FAST_OTPUSER_IS_EQUAL_IDX 			(FAST_OTP_IDX_OFFSET+13)	// N
#define FAST_OTPUSER_VERIFY_CODE_IDX 		(FAST_OTP_IDX_OFFSET+14)	// O
#define FAST_OTPUSER_GET_BLOCK_STATE_IDX 	(FAST_OTP_IDX_OFFSET+15)	// P
#define FAST_OTPUSER_ISUSER_BLOCKED_IDX 	(FAST_OTP_IDX_OFFSET+16)	// Q

// format J <username> <secret> 
int32_t fastNewOtpUser(const char *str) {
	OtpUserS *otpUser = NULL;
	char secret[FAST_FULL_SECRET_LEN+1], *secretPtr=NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastSecretStr(secret, &secretPtr, str, FAST_USER_NAME_LEN, FAST_SECRET_LEN);
	if (Debug)
		printf("newOtpUser with the following parameters: user name '%s', secret '%s'\n", userNamePtr, secretPtr);
	if (OtpUser_NewSimpleUser(&otpUser, (unsigned char *)secretPtr) == false) {
		return false;
	}
	if (EntityManager_IsEntityInList(EntityListData, userNamePtr) == false)
		OtpUser_FreeUser((void *)otpUser);
	else {
		EntityManager_RemoveProperty(EntityListData, userNamePtr, OTP_PROPERTY_NAME, true);
		EntityManager_RegisterProperty(EntityListData, userNamePtr, OTP_PROPERTY_NAME, otpUser);
	}
	return true;
}

// format K <username>
int32_t fastFreeOtpProperty(const char *str) {
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastFreeOtpProperty with the following parameters: userName '%s'\n", userNamePtr);
	EntityManager_RemoveProperty(EntityListData, userNamePtr, OTP_PROPERTY_NAME, true);
	return true;
}

// format L <user name> <state>
int32_t fastSetOtpUserState(const char *str) {
	int32_t state=-1;
	OtpUserS *otpUser = NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char stateStr[FAST_ONE_DIGIT_LEN+1], *tmpPtr=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(stateStr, &tmpPtr, str, FAST_USER_NAME_LEN, FAST_ONE_DIGIT_LEN, false);
	state = (stateStr[0] % 2);
	if (Debug)
		printf("fastsetOtpUserState with the following parameters: userName '%s' state %d\n", userNamePtr, state);
	EntityManager_GetProperty(EntityListData, userNamePtr,  OTP_PROPERTY_NAME, (void **)&otpUser);
	OtpUser_SetBlockedState(otpUser, state);
	return true;
}

// format M <user name> <otp type> <time factor>
int32_t fastOtpUserCanCheckCode(const char *str) {
	int32_t otpType=-1, timeFactor=-1;
	bool tmp=false;
	OtpUserS *otpUser = NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char otpTypeStr[FAST_ONE_DIGIT_LEN+1], *tmpPtr=NULL;
	char timeFactorStr[FAST_TWO_DIGITS_LEN+1];

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(otpTypeStr, &tmpPtr, str, FAST_USER_NAME_LEN, FAST_ONE_DIGIT_LEN, false);
	setFastStr(timeFactorStr, &tmpPtr, str, FAST_USER_NAME_LEN+FAST_ONE_DIGIT_LEN, FAST_TWO_DIGITS_LEN, false);
	otpType = (otpTypeStr[0] % 2);
	if (tmpPtr != NULL && strlen(timeFactorStr) >= 2)
		timeFactor = timeFactorStr[0] * 256 + timeFactorStr[1];
	else
		timeFactor = -1;
	if (Debug)
		printf("fastOtpUserCanCheckCode with the following parameters: userName '%s' otp type %d, time factor %d\n", userNamePtr, otpType, timeFactor);
	EntityManager_GetProperty(EntityListData, userNamePtr,  OTP_PROPERTY_NAME, (void **)&otpUser);
	return true ;
}

// format N <name1> <name2>
int32_t fastIsEqualOtpUsers(const char *str) {
	void *user[2]= {NULL, NULL};
	void *data1 = NULL, *data2 = NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr[2];

	setFastStr(userName, &userNamePtr[0], str, 0, FAST_USER_NAME_LEN, true);
	setFastStr(userName, &userNamePtr[1], str, FAST_USER_NAME_LEN, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastIsEqualOtpUsers with the following parameters: otpUser1 '%s' otpUser2 '%s'\n", userNamePtr[0], userNamePtr[1]);
	EntityManager_GetProperty(EntityListData, user[0], OTP_PROPERTY_NAME, &data1);
	EntityManager_GetProperty(EntityListData, user[1], OTP_PROPERTY_NAME, &data2);
	OtpUserTest_IsEqual(data1, data2);
	return true;
}

// format O <user name> <secret> <otp type>
int32_t fastOtpUserVerifyCode(const char *str) {
	int32_t otpType=-1;
	OtpUserS *otpUser = NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;
	char secretStr[FAST_FULL_SECRET_LEN+1], *secretPtr=NULL;
	char otpTypeStr[FAST_ONE_DIGIT_LEN+1], *tmpPtr=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	setFastSecretStr(secretStr, &secretPtr, str, FAST_USER_NAME_LEN, FAST_SECRET_LEN);
	setFastStr(otpTypeStr, &tmpPtr, str, FAST_USER_NAME_LEN+FAST_SECRET_LEN, FAST_ONE_DIGIT_LEN, false);
	otpType = (otpTypeStr[0] % 2);
	if (Debug)
		printf("fastOtpUserVerifyCode with the following parameters: userName '%s' secret '%s', otp type %d\n", userNamePtr, secretPtr, otpType);
	EntityManager_GetProperty(EntityListData, userNamePtr, OTP_PROPERTY_NAME, (void **)&otpUser);
	return OtpUser_VerifyCode(otpUser, secretPtr, otpType);
}

// format P/Q <user name>
int32_t fastGetOtpUserState(const char *str, int32_t type) {
	OtpUserS *otpUser = NULL;
	char userName[MAX_STR_LEN+1], *userNamePtr=NULL;

	setFastStr(userName, &userNamePtr, str, 0, FAST_USER_NAME_LEN, true);
	if (Debug)
		printf("fastGetOtpUserState with the following parameters: userName '%s'\n", userNamePtr);
	EntityManager_GetProperty(EntityListData, userNamePtr,  OTP_PROPERTY_NAME, (void **)&otpUser);
	if (type == FAST_OTPUSER_GET_BLOCK_STATE_IDX)
		OtpUser_GetBlockState(otpUser);
	else
		OtpUser_IsUserBlocked(otpUser);
	return true;
}

int32_t fastTestOtpUser(const char *callStr, const char *fileName, int32_t line, char *str) {
	int32_t found = false;
	int32_t callIdx = callStr[0];
	char *dataPtr=NULL;

	if (getParams("fastTestOtpUser", fileName, line, str, NUM_OF_FAST_PARAMS) == false)
		return false;
	if (Params[0] != NULL && strlen(Params[0])>1)
		dataPtr = &(Params[0][1]);
	switch (callIdx) {
		case FAST_OTPUSER_NEW_USER_IDX:
			fastNewOtpUser(dataPtr);
			found = true;
			break;
		case FAST_OTPUSER_FREE_IDX:
			fastFreeOtpProperty(dataPtr);
			found = true;
			break;
		case FAST_OTPUSER_SET_BLOCK_STATE_IDX:
			fastSetOtpUserState(dataPtr);
			found = true;
			break;
		case FAST_OTPUSER_CAN_CHECK_CODE_IDX:
			fastOtpUserCanCheckCode(dataPtr);
			found = true;
			break;
		case FAST_OTPUSER_IS_EQUAL_IDX:
			fastIsEqualOtpUsers(dataPtr);
			found = true;
			break;
		case FAST_OTPUSER_VERIFY_CODE_IDX:
			fastOtpUserVerifyCode(dataPtr);
			found = true;
			break;
		case FAST_OTPUSER_GET_BLOCK_STATE_IDX:
		case FAST_OTPUSER_ISUSER_BLOCKED_IDX:
			fastGetOtpUserState(dataPtr, callIdx);
			found = true;
			break;
	}
	return found;
}