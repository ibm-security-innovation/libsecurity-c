#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "libsecurity/utils/utils.h"
#include "libsecurity/otp/otpUser.h"

#include "hashtab/standard.h"
#include "hashtab/hashtab.h"

#define MAX_OTP_USER_STR_LEN 200

#define OTP_USER_STRUCT_FMT "%s %d"

#define DEFAULT_START_COUNTER 1000
#define DEFAULT_THROTTLING_LEN 10
#define DEFAULT_THROTTLING_SEC 1
#define DEFAULT_UNBLOCK_SEC 3600
// 0 means manuel unblock
#define MANUEL_UNBLOCK_SEC 0

#define DEFAULT_HOTP_WINDOWS_SIZE 3
#define DEFAULT_TOTP_WINDOWS_SIZE_SEC -30
#define DEFAULT_CONS_ERROR_COUNTER 0

#define MIN_THROTTLING_COUNTER 10
#define MAX_THROTTLING_COUNTER 10000
#define MIN_THROTTLING_SEC 0
#define MAX_THROTTLING_SEC 5
#define MIN_HOTP_WIDOWS_SIZE 1
// the search window will be inclusive this value
#define MAX_HOTP_WIDOWS_SIZE 5
#define MIN_TOTP_WIDOWS_SIZE_SEC -240
#define MAX_TOTP_WIDOWS_SIZE_SEC 240
#define MAX_UNBLOCK_SEC 3600

#define TROTTLING_PREFIX "thr-"
#define OTP_MAIN_PREFIX "om-"
#define OTPUSER_PREFIX_FMT "%s%s"
#define THROTTLING_STRUCT_PRINT_FMT                                                                                                        \
  "%" PRId32 " %" PRId32 " %" MY_PRId64 " %" MY_PRId64 " %" PRId32 " %" PRId32 " %" PRId32 " %" MY_PRId64 " %" PRId32 " %s"
  // old use   "%" PRId32 " %" PRId32 " %ld %lu %" PRId32 " %" PRId32 " %" PRId32 " %lu %" PRId32 " %s"
#define THROTTLING_STRUCT_SCAN_FMT                                                                                                         \
  "%" SCNd32 " %" SCNd32 " %" MY_SCNd64 " %" MY_SCNd64 " %" SCNd32 " %" SCNd32 " %" SCNd32 " %" MY_SCNd64 " %" SCNd32 " %s"
// old use    "%" SCNd32 " %" SCNd32 " %ld %lu %" SCNd32 " %" SCNd32 " %" SCNd32 " %lu %" SCNd32 " %s"

#define LAST_TOTP_CODE_STR "N.A."

#define NUM_OF_INT_ITEMS_INTHROTLING 6
#define NUM_OF_LONG_ITEMS_INTHROTLING 3

#define OTP_USER_DEBUG 0
#define debug_print1(fmt, ...)                                                                                                             \
  {                                                                                                                                        \
    if (OTP_USER_DEBUG) DEBUG(fmt, __VA_ARGS__);                                                                                           \
  }

extern bool OtpUser_TestMode;

STATIC void printThrottlingParameters(FILE *ofp, const throttelingS *t);
STATIC void otpUserStructToStr(const OtpUserS *user, char *str, int16_t maxStrLen);
STATIC void throttlingStructToStr(const throttelingS *thr, char *str, int16_t maxStrLen);
STATIC bool verifyUserCodeHelper(OtpUserS *u, const char *code, OtpType otpType, int16_t timeFactorSec);
#ifdef STATIC_F // for testing
STATIC MicroSecTimeStamp getAutoUnBlockedTimer(OtpUserS *u);
#endif
STATIC void newThrottle(throttelingS **thr, int16_t cliffLen, int16_t durationSec, int16_t autoUnblockSec, int16_t hotpWindowSize, int16_t totpWindowSize);
STATIC void freeThrottle(throttelingS *thr);
STATIC bool initAutoUnblockTimer(OtpUserS *u);
STATIC bool checkAndUpdateUnBlockStateHelper(OtpUserS *u, int16_t timeOffset);
STATIC bool findHotpCodeMatch(OtpUserS *u, const char *code, int16_t size, bool *found, int16_t *match_idx);
STATIC bool canCheckCode(OtpUserS *user, OtpType otpType, int16_t timeFactorSec, bool *canCheck);
STATIC bool findTotpCodeMatch(OtpUserS *u, const char *code, int16_t timeOffsetSec, bool *found);
STATIC bool handleErrorCode(OtpUserS *u, OtpType otpType);
STATIC bool handleOkCode(OtpUserS *u, const char *code, OtpType otpType, int16_t offset);
STATIC bool isUserBlockedHelper(OtpUserS *user, int16_t offsetTime);
STATIC bool updateThrottleFromStorage(void **user, char *val);
