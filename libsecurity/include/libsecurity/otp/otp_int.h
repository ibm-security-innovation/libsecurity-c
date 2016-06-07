#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "libsecurity/utils/utils.h"
#include "libsecurity/otp/otp.h"

#define DEFAULT_NUM_OF_DIGITS 6
#define DEFAULT_INTERVAL_SEC 30
#define MIN_NUM_OF_DIGITS 6 // RFC 4226 R4
#define MAX_NUM_OF_DIGITS 10
#define MIN_INTERVAL_SEC 10
#define MAX_INTERVAL_SEC 60

#define MIN_DIGEST_IDX 0
#define SHA1_FUNC_IDX 0
#define MD5_FUNC_IDX 1
#define SHA256_FUNC_IDX 2
#define MAX_DIGEST_IDX 2

#define DEFAULT_HASH_FUNC_IDX SHA1_FUNC_IDX

#define RANDOM_LEN 6

#define MAX_OTP_STR_LEN 155
#define TOTP_PREFIX "t-"
#define HOTP_PREFIX "h-"
#define OTP_PREFIX_FMT "%s%s"
#define OTP_STRUCT_FMT "%s\n%d\n%d\n"
#define TOTP_STRUCT_FMT "%s %d %d %d"
#define HOTP_STRUCT_FMT "%s %d %d %ld"

#define OTP_DEBUG 0
#define debug_print(fmt, ...)                                                                                                              \
  {                                                                                                                                        \
    if (OTP_DEBUG) DEBUG(fmt, __VA_ARGS__);                                                                                                \
  }

extern bool Otp_TestMode;

STATIC bool isValidDigits(int16_t val);
STATIC bool isValidDigest(int16_t val);
STATIC bool isValidOtpSecret(const unsigned char *secret);
STATIC bool isValidOtp(const OtpS *otp);
STATIC bool setSecretStr(unsigned char fixedSecret[crypto_auth_BYTES + 1], const unsigned char *secret);
STATIC bool generateHmac(const OtpS *otp, char *key, char **val);
STATIC MicroSecTimeStamp timeCode(const TotpS *tp, MicroSecTimeStamp t);
STATIC void totpStructToStr(const TotpS *totp, char *str, int16_t maxStrLen);
STATIC bool isValidInterval(int16_t val);
STATIC bool isValidTotp(const TotpS *totp);
STATIC void hotpStructToStr(const HotpS *hotp, char *str, int16_t maxStrLen);
