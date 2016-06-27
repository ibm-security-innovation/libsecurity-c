#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#include <assert.h>

#include "libsecurity/libsecurity/libsecurity_params.h"
#include "libsecurity/utils/hwAdapters.h"
#include "libsecurity/utils/crypto.h"

#include "hashtab/standard.h"
#include "hashtab/hashtab.h"

#define H_TAB_SIZE 8

#ifndef __GNUC__
#define __attribute__(x) /*nothing*/
#endif

extern void logprintf(const char *format, ...) __attribute__((format(printf, 1, 2)));
extern void logprintva(const char *format, va_list args) __attribute__((format(printf, 1, 0)));

#define ERR_STR_LEN 255

#define UTILS_STR_LEN_SIZE 3

extern char errStr[ERR_STR_LEN];

#define MIN_PASSWORD_LENGTH 6 // at least 2 chars, 2 digits and 2 extra chars
#define MAX_PASSWORD_LENGTH 255

typedef enum {STRENGTH_NIL=0, STRENGTH_POOR, STRENGTH_SUFFICIENT, STRENGTH_GOOD, STRENGTH_EXCELLENT} PasswordStreangthType;

typedef struct {
  char *name;
  bool (*testFunc)(void);
} Utils_TestFuncS;

typedef int64_t MicroSecTimeStamp;

#ifdef MBED_OS
#define MY_PRId64 "08lx %08lx" // mbed K64F bug with 64b print
#define MY_SCNd64 "08lx %08lx"
#else
#define MY_PRId64 "08x %08x"
#define MY_SCNd64 "08x %08x"
#endif

typedef int32_t SecTimeStamp;

#define DEBUG(fmt, ...)                                                                                                                    \
  do {                                                                                                                                     \
    fprintf(stderr, "%s: ", __FILE__);                                                                                                     \
    fprintf(stderr, fmt, __VA_ARGS__);                                                                                                     \
  } while (0)

#ifdef __cplusplus
extern "C" {
#endif

bool Utils_CheckNameValidity(const char *errStrPrefix, const char *name, int16_t minLen, int16_t maxLen);
bool Utils_IsPrefixValid(const char *errStrPrefix, const char *prefix);
bool Utils_GetIpV4Address(const char *ipStr, int16_t addressVec[4], int32_t *addr);
bool Utils_IsIpStrValid(const char *ipStr);

PasswordStreangthType Utils_CalculatePasswordStrength(const unsigned char *sPwd, const unsigned char *userName);

void Utils_AddPrefixToErrorStr(const char *str);

bool Utils_CreateAndCopyString(char **dst, const char *src, const int16_t len);
bool Utils_CreateAndCopyUcString(unsigned char **dst, const unsigned char *src, int16_t len);
void Utils_AbortCallBack(void (*cb)(const char *msg));
void Utils_Abort(const char *msg);
void Utils_MallocCallBack(bool (*cb)(void **dst, int16_t len));
bool Utils_Malloc(void **dst, int16_t len);
void Utils_FreeCallBack(void (*cb)(void *ptr));
void Utils_Free(void *ptr);

bool Utils_Sleep(int16_t sec, MicroSecTimeStamp nanosec);

MicroSecTimeStamp Utils_GetBeginningOfTime(void);
MicroSecTimeStamp Utils_GetFutureTimeuSec(SecTimeStamp addTimeSec);
MicroSecTimeStamp Utils_GetTimeNowInuSec(void);
MicroSecTimeStamp Utils_GetFutureTimeSec(SecTimeStamp addTimeSec);
MicroSecTimeStamp Utils_GetTimeNowInSec(void);

bool Utils_IsStringValid(const char *typeStr, const char *errStrPrefix, const char *str, int16_t minLen, int16_t maxLen);

bool Utils_GenerateCharArray(const unsigned char *str, int16_t len, unsigned char **caStr);
bool Utils_ConvertCharArrayToStr(const unsigned char *caStr, unsigned char **str);
bool Utils_GetCharArrayLen(const unsigned char *caStr, int16_t *len, int16_t minLen, int16_t maxLen);
bool Utils_SetCharArrayLen(unsigned char *caStr, int16_t len);

void Utils_PrintHexStr(FILE *ofp, const char *header, const unsigned char *str, int16_t len);
void Utils_PrintCharArray(FILE *ofp, const char *header, const unsigned char *str);
bool Utils_WriteCharArray(FILE *ofp, const unsigned char *str);
bool Utils_ReadCharArray(FILE *ofp, unsigned char *str, int16_t maxLen);
bool Utils_CharArrayCmp(const unsigned char *str1, const unsigned char *str2);

void Utils_PrintHash(const char *header, htab *t);
void Utils_PrintHashKeys(const char *header, const char *prefix, htab *t);
bool Utils_AddToHash(htab *t, const unsigned char *key, int16_t keyLen, void *val);
bool Utils_GetValFromHash(htab *t, const unsigned char *key, int16_t keyLen, void **val);
bool Utils_IsEqualHash(htab *t1, htab *t2);
bool Utils_DeleteKeyFromHash(htab *t, const unsigned char *key, int16_t keyLen);
void Utils_FreeHash(htab *t);
void Utils_FreeHashKeys(htab *t);

void Utils_DuplicateHash(htab *origHash, htab *newHash);

void Utils_FopenCallBack(FILE *(*cb)(const char *filename, const char *mode));
FILE *Utils_Fopen(const char *fileName, const char *mode);
void Utils_FcloseCallBack(int (*cb)(FILE *stream));
int Utils_Fclose(FILE *stream);
void Utils_RemoveFileCallBack(int (*cb)(const char *fileName));
int Utils_RemoveFile(const char *fileName);

char *Utils_Fgets(char *str, int16_t maxLen, FILE *ifp);

bool FileAdapters(void);

bool Utils_GenerateNewValidPassword(unsigned char **sPwd, int16_t pwdLen);

#ifdef __cplusplus
}
#endif
