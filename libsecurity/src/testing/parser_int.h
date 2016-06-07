#pragma once

// #include "crypto_hash.h"
#include "parser.h"
#include "libsecurity/accounts/accounts_int.h"
#include "libsecurity/otp/otpUser_int.h"
#include "libsecurity/otp/otp_int.h"
#include "libsecurity/acl/acl_int.h"

// #define true 	1
// #define false	0

#define MEGA_SECRET 			((undigned char *)"12345678")
#define STORGAE_PREFIX		"megaStore"
#define MEGA_FILE_NAME		"./megatmp.txt"

#define MAX_STR_LEN				512
#define LOG_MAX_STR_LEN			10

#define NUM_OF_FAST_PARAMS 	1
#define FAST_USER_NAME_LEN		1
#define FAST_PERMISSION_LEN	1
#define FAST_SECRET_LEN			2
#define FAST_FULL_SECRET_LEN	32  // duplicate the SECRET_LEN into the full secret
#define FAST_ONE_DIGIT_LEN		1
#define FAST_TWO_DIGITS_LEN		2
#define FAST_THREE_DIGITS_LEN	3
#define FAST_PREFIX_LEN			1


#define FAST_MAX_NUM_OF_USERS_LISTS		2
#define FAST_MAX_NUM_OF_GROUPS_LISTS	2

extern int Debug;

#define TEST_NULL_STR	"_"
#define TEST_NULL_CHAR	'a'

#define MAX_BUF_SIZE			512
#define MAX_NUM_OF_PARAMS	10
extern char Params[MAX_NUM_OF_PARAMS][MAX_BUF_SIZE];

#define MEGA_CMD_LEN				1
#define MODULE_START_IDX		5
#define PROPERTY_NAME_LEN			2
#define MEGA_CMD_STR_LEN		9 //MCMD-UM03
#define MEGA_CMD_PREFIX_STR		"CMD-"

typedef struct {
	int moduleIdx;
	char *propertyName;
}MoudlesNameS;

#define USER_CMD_MODULE_PREFIX				"UM"
#define USER_CMD_MODULE_IDX					0
#define AM_CMD_MODULE_PREFIX					"AM"
#define AM_CMD_MODULE_IDX						1
#define OTP_CMD_MODULE_PREFIX					"OP"
#define OTP_CMD_MODULE_IDX						2
#define PWD_CMD_MODULE_PREFIX					"PW"
#define PWD_CMD_MODULE_IDX						3

#define NUM_OF_USERS			8
#define NUM_OF_GROUPS		4
#define NUM_OF_RESOURCES		4
#define MAX_USER_NAME_LEM	32
extern char UserName[MAX_USER_NAME_LEM+1];

/* old use
#define NUM_OF_PREDEFINED_PREFIXES 3
extern char *Prefixes[NUM_OF_PREDEFINED_PREFIXES];
*/

#define TMP_FILE_DIR "./fast-files"
#define FILE_NAME "./tmp.txt"
#define SECRET ((unsigned char *)"12345678901234567890123456789012")
#define SALT ((unsigned char *)"salt")
#define MAX_NUM_OF_STORAGES	3
extern SecureStorageS Storage[MAX_NUM_OF_STORAGES];

#define STORE_IDX 	0
#define LOAD_IDX 		1
extern char *StoreLoadStr[2];

#define NUM_OF_CALL_FUNC_LEN 200 // 2 digits at most
#define MAX_ID_LEN 2 // 2 digits at most

extern EntityManager *EntityListData;

#define USER_IDX_OFFSET			0
#define OTP_IDX_OFFSET			100
#define OTPUSER_IDX_OFFSET 	120
#define FAST_USER_IDX_OFFSET	'a'
#define FAST_ACL_IDX_OFFSET		'u'
#define FAST_OTP_IDX_OFFSET		'A'
#define FAST_STORAGE_IDX_OFFSET	'R'
#define FAST_AM_IDX_OFFSET		'1'
#define FAST_PWD_IDX_OFFSET		'#'

#define MAX_NUM_OF_OTP 	10
extern OtpS *Otp[MAX_NUM_OF_OTP];


typedef struct {
	char *flag;
	int (*testFunc) (const char *callStr, const char *fileName, int line, char *str);
	int wasSet;
}FlagsS;


int getModuleCommandIdx(const char *data, int *moduleIdx, int *idx);
int getParams(const char *funcName, const char *fileName, int line, char *str, int numOfParams);
int getIdx(const char *fileName, int line, char *str, int maxLen, int *val);
int getInt64(const char *fileName, int line, char *str, int64_t *val);
int getNextValidLine(FILE *ifp, const char *fileName, int *line, char *str, int maxLen, int *ok);

int testUser(const char *callStr, const char *fileName, int line, char *str);
int createNewUser(const char *fileName, int line, char *str);
//int freeUser(const char *fileName, int line, char *str);
int storeLoadUser(int type, const char *fileName, int line, char *str);
//int isEqualUsers(const char *fileName, int line, char *str);

void initOtp();
void clearOtp();
int testOtp(const char *callStr, const char *fileName, int line, char *str);
void initUserOtp();
int testOtpUser(const char *callStr, const char *fileName, int line, char *str);
int testMegaCmd(const char *callStr, const char *fileName, int line, char *str);

int fastTestUser(const char *callStr, const char *fileName, int line, char *str);
int fastTestOtp(const char *callStr, const char *fileName, int line, char *str);
int fastTestOtpUser(const char *callStr, const char *fileName, int line, char *str);
int fastTestAm(const char *callStr, const char *fileName, int line, char *str);
int fastTestAcl(const char *callStr, const char *fileName, int line, char *str);
int fastTestStorage(const char *callStr, const char *fileName, int line, char *str);
int fastTestPwd(const char *callStr, const char *fileName, int line, char *str);

int isIdxValid(int minIdx, int maxIdx, int idx);

int runUserCmd(const char *fileName, int line, char *str, int idx);
int runAmCmd(const char *fileName, int line, char *str, int idx);
int runOtpCmd(const char *fileName, int line, char *str, int idx);

int setFastStr(char *str, char **ptr, const char *data, int start, int maxLen, int strechStr);
int setFastSecretStr(char *str, char **ptr, const char *data, int start, int maxLen);
int getFreeOtpIdx();
void clearOtp();
int getFastIdx(const char *data, int start, int len, int max);

void fastInitAcl();
void fastInitOtp();
void fastClearAcl();
