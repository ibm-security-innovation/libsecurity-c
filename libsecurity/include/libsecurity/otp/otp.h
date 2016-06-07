#pragma once

#include <stdlib.h>
#include "libsecurity/storage/secureStorage.h"
#include "libsecurity/libsecurity/libsecurity_params.h"

#define MIN_SECRET_LEN 8 // TODO 16 // RFC 4226 R6, for OCRA examples it must be 8
#define MAX_SECRET_LEN 255

// One Time Password
typedef struct {
  unsigned char *Secret; // Assume a legal Secret key
  int16_t Digits; // Number of digits in the code. Default is 6
  int16_t DigestType; // Digest type, Default is sha1
} OtpS;

// Time-based One Time Password
typedef struct {
  int16_t Interval; // The time interval in seconds for OT, The default is 30
  // seconds (the standard)
  OtpS *BaseOtp;
} TotpS;

// Event-based HMAC One Time Password
typedef struct {
  int64_t Count;
  OtpS *BaseOtp;
} HotpS;

void Otp_Print(FILE *ofp, const char *header, const OtpS *otp);
bool Otp_NewAdvance(OtpS **otp, const unsigned char *secret, int16_t numOfDigits, int16_t digestType);
bool Otp_New(OtpS **otp, const unsigned char *secret);
void Otp_Free(OtpS *otp);
bool Otp_Generate(const OtpS *otp, int64_t seed, char **val);
bool Otp_IsEqual(const OtpS *otp1, const OtpS *otp2);
bool Otp_ReplaceSecret(OtpS *otp, const unsigned char *secret);

void Otp_PrintTotp(FILE *ofp, const char *header, const TotpS *totp);
bool Otp_NewTotp(TotpS **totp, const unsigned char *secret);
void Otp_FreeTotp(TotpS *totp);
bool Otp_GetTotpAtTime(const TotpS *totp, MicroSecTimeStamp time, char **val);
bool Otp_GetTotpNow(const TotpS *totp, char **val);
bool Otp_IsEqualTotp(const TotpS *totp1, const TotpS *totp2);
bool Otp_StoreTotp(const TotpS *totp, const SecureStorageS *storage, const char *prefix);
bool Otp_LoadTotp(void **t, const SecureStorageS *storage, const char *prefix, char **retName);

void Otp_PrintHotp(FILE *ofp, const char *header, const HotpS *hotp);
bool Otp_NewHotp(HotpS **hotp, const unsigned char *secret, int64_t count);
void Otp_FreeHotp(HotpS *hotp);
bool Otp_GetHotpAtCount(HotpS *hotp, int64_t count, char **val);
bool Otp_GetHotpNext(HotpS *hotp, char **val);
bool Otp_HotpRandom(HotpS *hotp, char **val);
bool Otp_IsEqualHotp(const HotpS *hotp1, const HotpS *hotp2);
bool Otp_StoreHotp(const HotpS *hotp, const SecureStorageS *storage, const char *prefix);
bool Otp_LoadHotp(void **hotp, const SecureStorageS *storage, const char *prefix, char **retName);
