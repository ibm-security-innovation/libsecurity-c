#include "parser_int.h"

OtpS *Otp[MAX_NUM_OF_OTP];

#define MAX_NUM_OF_DIGITS	10
#define MAX_NUM_OF_DIGEST	3

#define FAST_OTP_NEW_IDX 					(FAST_OTP_IDX_OFFSET+0) // A
#define FAST_OTP_NEW_ADV_IDX			 	(FAST_OTP_IDX_OFFSET+1) // B
#define FAST_OTP_FREE_IDX 					(FAST_OTP_IDX_OFFSET+2) // C
#define FAST_OTP_GENERATE_IDX 				(FAST_OTP_IDX_OFFSET+3) // D
#define FAST_OTP_IS_EQUAL_IDX 				(FAST_OTP_IDX_OFFSET+4) // E
#define FAST_OTP_REPLACE_SECRET_IDX 		(FAST_OTP_IDX_OFFSET+5) // F

void fastInitOtp(){
	int32_t i=0;

	for (i=0 ; i<MAX_NUM_OF_OTP ; i++)
		Otp[i] = NULL;
}

void clearOtp() {
	int32_t i=0;

	for (i=0 ; i<MAX_NUM_OF_OTP ; i++) {
		Otp_Free(Otp[i]);
	}
}

int32_t getFreeOtpIdx() {
	int32_t i=0, defaultOtpIdx=2;

	for (i=0 ; i<MAX_NUM_OF_OTP ; i++) {
		if (Otp[i] == NULL) {
			return i ;
		}
	}
	Otp_Free((void *) Otp[defaultOtpIdx]);
	Otp[defaultOtpIdx] = NULL;
	return defaultOtpIdx;
}

int32_t getFastIdx(const char *data, int32_t start, int32_t len, int32_t max){
	int32_t idx=-1;
	char idxStr[FAST_ONE_DIGIT_LEN+1], *tmpPtr=NULL;

	setFastStr(idxStr, &tmpPtr, data, start, len, false);
	idx = idxStr[0]-'0';
	if (idx > max-1 || idx < 0)
		idx=0;
	return idx;
}

// format A <secret> // note: if the secret is TEST_NULL_STR, use it as NULL
int32_t fastNewOtp(const char *str) {
	int32_t idx=-1;
	char secret[MAX_STR_LEN+1], *secretPtr=NULL;

	setFastStr(secret, &secretPtr, str, 0, FAST_SECRET_LEN, true);
	if (Debug)
		printf("fastNewOtp with the following parameters: secret '%s'\n", secretPtr);
	idx = getFreeOtpIdx();
	Otp_New(&(Otp[idx]), (unsigned char *)secretPtr);
	return true;
}

// format B <secret> <num of digits> <digest type>
int32_t fastNewAdvOtp(const char *str) {
	int32_t idx=-1, numOfDigits=0, digestType=0;
	char secret[MAX_STR_LEN+1], *secretPtr=NULL;
	char numOfDigitsStr[FAST_ONE_DIGIT_LEN+1], *tmpPtr=NULL;
	char digestTypeStr[FAST_ONE_DIGIT_LEN+1];

	setFastStr(secret, &secretPtr, str, 0, FAST_SECRET_LEN, true);
	setFastStr(numOfDigitsStr, &tmpPtr, str, FAST_SECRET_LEN, FAST_ONE_DIGIT_LEN, false);
	setFastStr(digestTypeStr, &tmpPtr, str, FAST_SECRET_LEN+FAST_ONE_DIGIT_LEN, FAST_ONE_DIGIT_LEN, false);
	numOfDigits = (numOfDigitsStr[0]-'0') % MAX_NUM_OF_DIGITS;
	digestType = (digestTypeStr[0]-'0') % MAX_NUM_OF_DIGEST;
	if (Debug)
		printf("fastNewAdvOtp with the following parameters: secret '%s' num of digites %d, digest type %d\n", secretPtr, numOfDigits, digestType);
	idx = getFreeOtpIdx();
	Otp_NewAdvance(&(Otp[idx]), (unsigned char *)secretPtr, numOfDigits, digestType);
	return true;
}

// format C <idx> // note: if the id is not in range, use it as NULL
int32_t fastFreeOtp(const char *str) {
	int32_t otpIdx = 0;

	otpIdx = getFastIdx(str, 0, FAST_ONE_DIGIT_LEN, MAX_NUM_OF_OTP);
	if (Debug)
		printf("fastFreeOtp with the following parameters: otp idx %d\n", otpIdx);
	Otp_Free((void *)Otp[otpIdx]);
	Otp[otpIdx] = NULL;
	return true;
}

// format D <idx> <seed> // note: if the idx is not in range, use it as NULL
int32_t fastGenerateOtp(const char *fileName, int32_t line, char *str) {
	int32_t otpIdx=-1;
	int64_t seed=0;
	char *val=NULL;
	char seedStr[FAST_TWO_DIGITS_LEN+1], *tmpPtr=NULL;

	otpIdx = getFastIdx(str, 0, FAST_ONE_DIGIT_LEN, MAX_NUM_OF_OTP);
	setFastStr(seedStr, &tmpPtr, str, FAST_ONE_DIGIT_LEN, FAST_TWO_DIGITS_LEN, false);
	if (getInt64(fileName, line, seedStr, &seed) == false)
		return false;
	if (Debug)
		printf("fastGenerateOtp with the following parameters: otp idx %d, seed %ld\n", otpIdx, seed);
	if (Otp_Generate(Otp[otpIdx], seed, &val) == true)
		Utils_Free((void *)val);
	return true;
}

// format E <idx1> <idx2>
// 	note: if the idx is not in range, use it as NULL
int32_t fastIsEqualOtps(const char *str) {
	int32_t i=0;
	int32_t otpIdx[2] = {-1, -1};
	OtpS *otps[2] = {NULL, NULL};

	otpIdx[0] = getFastIdx(str, 0, FAST_ONE_DIGIT_LEN, MAX_NUM_OF_OTP);
	otpIdx[1] = getFastIdx(str, FAST_ONE_DIGIT_LEN, FAST_ONE_DIGIT_LEN, MAX_NUM_OF_OTP);
	for (i=0 ; i<2 ; i++) {
		if (otpIdx[i] > MAX_NUM_OF_OTP-1 || otpIdx[i] < 0)
			otpIdx[i]=0;
		if (otpIdx[i] == (i+1))
			otps[i] = NULL;
		else
			otps[i] = Otp[otpIdx[i]];
	}
	if (Debug)
		printf("Compare OTPs with the following parameters: otp 1 idx %d, otp 2 idx %d\n", otpIdx[0], otpIdx[1]);
	Otp_IsEqual(otps[0], otps[1]);
	return true;
}

// format F <idx> <secret> 
// 	note: if the idx is not in range, use it as NULL
int32_t fastReplaceSecret(const char *str) {
	int32_t otpIdx=-1;
	char secret[MAX_STR_LEN+1], *secretPtr=NULL;
	OtpS *otp = NULL;

	otpIdx = getFastIdx(str, 0, FAST_ONE_DIGIT_LEN, MAX_NUM_OF_OTP);
	if (otpIdx == 4)
		otp = NULL;
	else
		otp = Otp[otpIdx];
	setFastStr(secret, &secretPtr, str, FAST_ONE_DIGIT_LEN, FAST_SECRET_LEN, true);
	if (Debug)
		printf("Otp_ReplaceSecret with the following parameters: secret otp idx %d, '%s'\n", otpIdx, secretPtr);
	Otp_ReplaceSecret(otp, (unsigned char *)secretPtr);
	return true;
}

int32_t fastTestOtp(const char *callStr, const char *fileName, int32_t line, char *str) {
	int32_t found = false;
	int32_t callIdx = callStr[0];
	char *dataPtr=NULL;

	if (getParams("fastTestOtp", fileName, line, str, NUM_OF_FAST_PARAMS) == false)
		return false;
	if (Params[0] != NULL && strlen(Params[0])>1)
		dataPtr = &(Params[0][1]);
	switch (callIdx) {
		case FAST_OTP_NEW_IDX:
			fastNewOtp(dataPtr);
			found = true;
			break;
		case FAST_OTP_NEW_ADV_IDX:
			fastNewAdvOtp(dataPtr);
			found = true;
			break;
		case FAST_OTP_FREE_IDX:
			fastFreeOtp(dataPtr);
			found = true;
			break;
		case FAST_OTP_GENERATE_IDX:
			fastGenerateOtp(fileName, line, dataPtr);
			found = true;
			break;
		case FAST_OTP_IS_EQUAL_IDX:
			fastIsEqualOtps(dataPtr);
			found = true;
			break;
		case FAST_OTP_REPLACE_SECRET_IDX:
			fastReplaceSecret(dataPtr);
			found = true;
			break;
	}
	return found;
}