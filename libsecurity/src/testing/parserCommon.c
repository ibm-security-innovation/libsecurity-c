#include "parser_int.h"

/*
#include "crypto_auth_hmacsha256.h"
#include "crypto_auth.h"
#include "randombytes.h"
*/

int32_t Debug=false;
#define MEGA_FUNC_IDX	3

MoudlesNameS Modules[] = {
	{USER_CMD_MODULE_IDX, USER_CMD_MODULE_PREFIX},
	{AM_CMD_MODULE_IDX, AM_CMD_MODULE_PREFIX},
	{OTP_CMD_MODULE_IDX, OTP_CMD_MODULE_PREFIX},
	{PWD_CMD_MODULE_IDX, PWD_CMD_MODULE_PREFIX}
};

FlagsS flags[] = {
//	{"user", testUser, false}, 
//	{"otp", testOtp, false}, 
//	{"otpuser", testOtpUser, false}, 
//	{"mega", testMegaCmd, false},
	{"fastuser", fastTestUser, false},
	{"fastotp", fastTestOtp, false},
	{"fastotpuser", fastTestOtpUser, false},
	{"fastam", fastTestAm, false},
	{"fastacl", fastTestAcl, false},
	{"faststorage", fastTestStorage, false},
	{"fastpwd", fastTestPwd, false}
};

char OtherData[MAX_BUF_SIZE];
// old use char *Prefixes[NUM_OF_PREDEFINED_PREFIXES] = {"prefix1", "user2", "the prefix3"};
SecureStorageS Storage[MAX_NUM_OF_STORAGES];
char *StoreLoadStr[2] = {"Store", "Load"};
EntityManager entityManagerTmp, *EntityListData;
char Params[MAX_NUM_OF_PARAMS][MAX_BUF_SIZE];
char UserName[MAX_USER_NAME_LEM+1];

// its a strict format MCMD-XXNN XX is the Module name and NN is the index of the command
int32_t getModuleCommandIdx(const char *data, int32_t *moduleIdx, int32_t *idx) {
	int32_t i=0, len=0, found = false, numOfModules = sizeof(Modules) / sizeof(MoudlesNameS);
	char propertyName[PROPERTY_NAME_LEN+1];

	len = strlen(data);
	if (len != MEGA_CMD_STR_LEN || !isdigit(data[MEGA_CMD_STR_LEN-1]) ||
			!isdigit(data[MEGA_CMD_STR_LEN-2])) {
		if (Debug)
			printf("Command is not OK: '%s'\n", data);
		return false;
	}
	snprintf(propertyName, PROPERTY_NAME_LEN+1, "%s", &(data[MODULE_START_IDX]));
	propertyName[PROPERTY_NAME_LEN] = 0;
	for (i=0 ; i<numOfModules ; i++) {
		if (strcmp(propertyName, Modules[i].propertyName) == 0){
			found = true;
			*moduleIdx = i;
			break;
		}
	}
	if (found == false) {
		if (Debug)
			printf("Command '%s' is not OK, module '%s' wasn't found\n", data, propertyName);
		return false;
	}
	*idx = (data[MEGA_CMD_STR_LEN-2] - '0') * 10 + (data[MEGA_CMD_STR_LEN-1] - '0');
//	if (Debug)
//		printf("Command '%s', module '%s' command index %d\n", data, propertyName, *idx);
	return true;
}

int32_t getParams(const char *funcName, const char *fileName, int32_t line, char *str, int32_t numOfParams){
	int32_t len=0;

	if (numOfParams > MAX_NUM_OF_PARAMS-1) {
		printf("Too many parameters in call from '%s' %d, exit\n", funcName, len);
		exit(-1);
	}
	len=sscanf(str, "%s %s %s %s %s %s %s %s %s %s", 
		Params[0], Params[1], Params[2], Params[3], Params[4], Params[5],
		Params[6], Params[7], Params[8], Params[9]);
	if (len != numOfParams) {
		if (Debug)
			printf("File '%s', line %d, Illegal %s command, the command '%s', contains %d parameters != %d\n", 
				fileName, line, funcName, str, len, numOfParams);
		return false;
	}
	return true;
}

// note: secure storage 0 is null
void init() {
	int32_t i=0, j=0;
	char userName[MAX_STR_LEN+1], *namePtr=NULL ;
	char groupName[MAX_STR_LEN+1], *namePtr1=NULL, str[10];

	EntityManager_New(&entityManagerTmp);
	EntityListData = &entityManagerTmp;
	for (i=0 ; i<NUM_OF_USERS ; i++) {
		snprintf(str, 10, "%c", 'a' + i);
		setFastStr(userName, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
		if (namePtr == NULL)
			continue;
		EntityManager_AddUser(EntityListData, namePtr);
	}
	for (i=0 ; i<NUM_OF_GROUPS ; i++) {
		snprintf(str, 10, "%c", 'a' + i);
		setFastStr(groupName, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
		EntityManager_AddGroup(EntityListData, namePtr);
		for (j=0 ; j<i && j<NUM_OF_USERS ; j++) {
			snprintf(str, 10, "%c", 'a' + j);
			setFastStr(userName, &namePtr1, str, 0, FAST_USER_NAME_LEN, true);
			EntityManager_AddUserToGroup(EntityListData, namePtr, namePtr1);
		}
	}
	for (i=0 ; i<NUM_OF_RESOURCES ; i++) {
		snprintf(str, 10, "%c", 'c' + i);
		setFastStr(userName, &namePtr, str, 0, FAST_USER_NAME_LEN, true);
		EntityManager_AddResource(EntityListData, namePtr);
	}
	for (i=1 ; i<MAX_NUM_OF_STORAGES ; i++) { // storage 0 will be NULL
		snprintf(UserName, MAX_USER_NAME_LEM, "store-%d", i);
		SecureStorage_NewStorage(SECRET, SALT, &(Storage[i]));
	}
	mkdir(TMP_FILE_DIR, 0700);
	fastInitOtp();
}

void freeParserData() {
	int32_t i=0;

	EntityManager_FreeAll(EntityListData);
	for (i=1 ; i<MAX_NUM_OF_STORAGES ; i++) {
		SecureStorage_FreeStorage((void *)(&(Storage[i])));
	}
	EntityManager_RemoveRegisteredPropertyList();
	clearOtp();
}

int32_t getIdx(const char *fileName, int32_t line, char *str, int32_t maxLen, int32_t *val) {
	if (strlen(str) > maxLen) {
		if (Debug)
			printf("File '%s', line %d, string length must be between 1-%d characters, but read '%s'\n", fileName, line, maxLen, str);
		return false;
	}
	*val = atoi(str);
	return true;
}

int32_t getInt64(const char *fileName, int32_t line, char *str, int64_t *val) {
	if (str == NULL || 
			strlen(str) > sizeof(int64_t)) {
		if (Debug)
			printf("File '%s', line %d, string length must be between 1-%d characters, but read '%s'\n", fileName, line, (int32_t)(sizeof(int64_t)), str);
		return false;
	}
	*val = atol(str);
	return true;
}

int32_t getNextValidLine(FILE *ifp, const char *fileName, int32_t *line, char *str, int32_t maxLen, int32_t *ok) {
	int32_t len=0;
	char ch=0;

	while (fgets(str, maxLen, ifp) != NULL) {
		*line = *line+1;
		//printf("%d: %s\n", *line, str);
		len = strlen(str)-1;
		if (len < 0)
			len = 0;
		ch = str[len];
		if (len > MAX_BUF_SIZE-1)
			len = MAX_BUF_SIZE-1;
		if (!feof(ifp))
			str[len]=0; // get rif of the last /n
		if (ch != '\n' && !feof(ifp)) { // read till the end of the line
			if (Debug)
				printf("File: '%s', line %d '%s' last character %d was too long, ignore\n", fileName, *line, str, ch);
			while(true) {
	    		ch = fgetc(ifp);
		      if(feof(ifp))
		      	return false;
		      if (ch == '\n')
		      	break;
		   }
			*ok = false;
			return true;
		}
//		if (Debug)
//			printf("Line: %d, Read '%s'\n", *line, str);
		*ok = true;
		return true;
	}
	return false;
}	

void test(const char *fileName) {
	int32_t i=0, ret=false, line =0, ok=false, len = sizeof(flags) / sizeof(FlagsS);
	FILE *ifp=NULL;
	char str[MAX_BUF_SIZE], callStr[MAX_BUF_SIZE];

	if (fileName == NULL)
		return;
	if ((ifp = fopen(fileName, "r"))==NULL) {
		printf("Error: Can't find input file '%s'\n", fileName);
		return;
	}
	while (getNextValidLine(ifp, fileName, &line, str, MAX_BUF_SIZE, &ok) == true) {
		if (ok == false)
			continue;
		if (sscanf(str, "%s", callStr) == 1) {
			callStr[MAX_BUF_SIZE-1]=0;
			if (strlen(callStr) > NUM_OF_CALL_FUNC_LEN && strstr(callStr, MEGA_CMD_PREFIX_STR) == NULL) {
				if (Debug)
					printf("Line %d, str '%s', Call str '%s' is not valid\n", line, str, callStr);
				continue;
			}
			for (i=0 ; i<len ; i++) {
				if (flags[i].wasSet == true) {
					if ((ret = flags[i].testFunc(callStr, fileName, line, str)) == true)
						break;
				}
			}
			if (ret == false && Debug)
				printf("Unhandled call '%s'\n", callStr);
		}
	}
	fclose(ifp);
}

int32_t parseFlags(int32_t argc, char *argv[]) {
	int32_t i=0, j=0, len = sizeof(flags) / sizeof(FlagsS);

//	for (i=0 ; i<len ; i++) {
//		flags[i].wasSet=false;
//	}
	for (i=2 ; i<argc ; i++) {
		for (j=0 ; j<len ; j++) {
			if (strcmp(argv[i], flags[j].flag) == 0) {
				flags[j].wasSet=true;
				printf("Flag '%s' was set\n", flags[j].flag);
			}
		}
	}
	if (argc < 2) {
		printf("Usage: %s test-file ", argv[0]);
		for (i=0 ; i<len ; i++) {
			printf( "[%s] ", flags[i].flag);
		}
		printf("\n");
		return false;
	}
	return true;
}

int32_t main(int32_t argc, char *argv[]) {
	Debug = true;
	Entity_TestMode = Accounts_TestMode = Otp_TestMode = Acl_TestMode = true;

	if (parseFlags(argc, argv) == false)
		return(-1);
	int32_t i=0;
	for (i=0 ; i<sizeof(flags)/sizeof(FlagsS) ; i++)
		printf("Fast flag: '%s' = %d\n", flags[i].flag, flags[i].wasSet);
	init();
	test(argv[1]);
	if (Debug)
		EntityManager_PrintFull(stdout, "EntityManager data:\n", EntityListData);
	freeParserData();
	return 1;
}