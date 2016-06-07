#pragma once

#include <stdlib.h>

#include "libsecurity/storage/secureStorage.h"
#include "libsecurity/entity/entityManager.h"
#include "libsecurity/otp/otp.h"

typedef struct {
  int16_t Cliff; // The provider will refuse connections from a user after T
  // unsuccessful
  // authentication attempts, Default is 100
  int16_t DurationSec; // Throttling duration in seconds between each wrong atempt
  MicroSecTimeStamp throttlingTimerHotp; // Next time the code could be verified for HOTP
  MicroSecTimeStamp throttlingTimerTotp; // Next time the code could be verified for TOTP
  int16_t CheckHotpWindow; // The window size of next codes to be checked before
  // reject the code as
  // not match
  int16_t consErrorCounter; // Counter of consecutive errors
  int16_t AutoUnblockSec; // Number of seconds to release block, 0 means that
  // the release should be
  // manuel
  MicroSecTimeStamp unblockTimer; // When to unblock the user
  int16_t CheckTotpWindowSec; // The window size in seconds tfor backword check:
  // to handle clock
  // driffts
  char *lastTotpCode; // save the last totp code to avoid reuse of code in the
  // same time period
} throttelingS;

typedef struct {
  bool Blocked;
  throttelingS *Throttle; // Handle all the throttle parameters
  HotpS *BaseHotp;
  TotpS *BaseTotp;
} OtpUserS;

typedef enum { HOTP_TYPE, TOTP_TYPE } OtpType;

void OtpUser_PrintUser(FILE *ofp, const char *header, const void *user);
bool OtpUser_IsValid(const OtpUserS *u);
bool OtpUser_NewUser(OtpUserS **user, const unsigned char *secret, bool lock, int16_t cliffLen, int16_t thrTimeSec, int16_t autoUnblockSec,
                     int16_t hotpWindowSize, int16_t totpWindowSize, int64_t startCount);
void OtpUser_FreeUser(void *user);
bool OtpUser_NewSimpleUser(OtpUserS **user, const unsigned char *secret);
bool OtpUser_GetBlockState(const OtpUserS *u);
bool OtpUser_SetBlockedState(OtpUserS *u, bool val);
bool OtpUser_VerifyCode(OtpUserS *u, const char *code, int16_t otpType);
bool OtpUser_IsUserBlocked(OtpUserS *user);
bool OtpUser_Store(const void *user, const SecureStorageS *storage, const char *prefix);
bool OtpUser_Load(void **user, const SecureStorageS *storage, const char *prefix, char **retName);

bool OtpUserTest_IsEqual(const void *u1, const void *u2);
bool OtpUserTest_IsEqualThrottling(const throttelingS *thr1, const throttelingS *thr2);
