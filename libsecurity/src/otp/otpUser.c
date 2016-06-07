// Package otp : A One Time Password (OTP) is a password that is valid for only one login session or transaction (and may be limited for a
// specific time period). The most important advantage that is addressed by OTPs is that, in contrast to static passwords, they are not
// vulnerable to replay attacks. A second major advantage is that a user who uses the same (or similar) password for multiple systems, is
// not made vulnerable on all of them, if the password for one of these is gained by an attacker.
// We implemented the 2 possible OTP implementations: A time based one time password algorithm (TOTP) and HMAC-based one time password
// algorithm (HOTP). Our OTP implementation is based on RFC 2289 for OTP in general, RFC 4226 for HOTP, and RFC 6238 for TOTP.
//
// The OTP implementation has three layers:
//  - The base layer includes the secret (e.g. SHA256, SHA1) and the number of digits in the digest.
//  - The second layer is the digest algorithm which is time based for TOTP and counter based for HOTP.
//  - The topmost layer includes the policy of handing unsuccessful authentication attempts. This includes blocking and throttling. The
//  blocking mechanism allows blocking users for a given duration of time (or until a manual unblock) after they pass a cliff which a limit
//  for the number of allowed consecutive unsuccessful authentication attempts. The throttling mechanism controls the delay between the
//  authentication request and the response. This delay is increased as the number of consecutive unsuccessful attempts grows to avoid brute
//  force password attacks. This layer includes also a time window for avoiding clock drifting errors when TOTPs are used.
//
// OTP per user:
//  Each OTP property has the following fields:
//  - Secret - the password itself
//  - Blocked  - a flag indicating if the user is blocked
//  - Throttling parameters - Handling of all the throttle parameters (details below), including:
//  - HOTP information: Current counter and OTP data (details below)
//  - TOTP information:  Interval, the time interval in seconds which is counted as a 'tick' (e.g. 30 seconds) and OTP data (details bellow)

#include "libsecurity/otp/otpUser_int.h"

bool OtpUser_TestMode = false;

STATIC void printThrottlingParameters(FILE *ofp, const throttelingS *t) {
  if (t == NULL) {
    assert(LIB_NAME "OTP throttling structure must not be NULL" && (false || OtpUser_TestMode));
    return;
  }
  fprintf(ofp, "OTP data: Cliff: %d, Durattion Sec: %d, throttlingTimerHotp %" MY_PRId64 ", throttlingTimerHotp %" MY_PRId64 ","
               " CheckHotpWindow %d, consErrorCounter %d, Auto unblock: %d, unblockTimer %" MY_PRId64 ", TotpWindowSizeSec %d, lastTotpCode '%s'\n",
          (int16_t)t->Cliff, (int16_t)t->DurationSec, (int32_t)(t->throttlingTimerHotp>>32), (int32_t)(t->throttlingTimerHotp), 
          (int32_t)(t->throttlingTimerTotp >> 32), (int32_t)t->throttlingTimerTotp,
          (int16_t)t->CheckHotpWindow, (int16_t)t->consErrorCounter, (int16_t)t->AutoUnblockSec, 
          (int32_t)(t->unblockTimer >> 32), (int32_t)t->unblockTimer, (int16_t)t->CheckTotpWindowSec, t->lastTotpCode);
}

void OtpUser_PrintUser(FILE *ofp, const char *header, const void *u) {
  const OtpUserS *user = NULL;

  fprintf(ofp, "%s", header);
  if (u == NULL) return;
  user = (const OtpUserS *)u;
  fprintf(ofp, "OTP data: is blocked: %d\n", user->Blocked);
  Otp_PrintHotp(ofp, "OTP data: ", user->BaseHotp);
  Otp_PrintTotp(ofp, "OTP data: ", user->BaseTotp);
  printThrottlingParameters(ofp, user->Throttle);
}

// Convert the user struct to string to be stored using the secure storage
STATIC void otpUserStructToStr(const OtpUserS *user, char *str, int16_t maxStrLen) {
  if (user == NULL || str == NULL) {
    assert(LIB_NAME "OTP user structure and input string must not be NULL" && (false || OtpUser_TestMode));
  }
  snprintf(str, maxStrLen, OTP_USER_STRUCT_FMT, user->BaseHotp->BaseOtp->Secret, (int)user->Blocked);
}

// Convert the throttling struct to string to be stored using the secure storage
STATIC void throttlingStructToStr(const throttelingS *thr, char *str, int16_t maxStrLen) {
  if (thr == NULL || str == NULL) {
    assert(LIB_NAME "OTP throtling structure and input string must not be NULL" && (false || OtpUser_TestMode));
    return;
  }
  snprintf(str, maxStrLen, THROTTLING_STRUCT_PRINT_FMT, (int32_t)thr->Cliff, (int32_t)thr->DurationSec, (int32_t)(thr->throttlingTimerHotp >> 32), (uint32_t)(thr->throttlingTimerHotp),
    (int32_t)(thr->throttlingTimerTotp >> 32), (uint32_t)thr->throttlingTimerTotp, (int32_t)thr->CheckHotpWindow, (int32_t)thr->consErrorCounter,
    (int32_t)thr->AutoUnblockSec, (int32_t)(thr->unblockTimer >> 32), (uint32_t)thr->unblockTimer, (int32_t)thr->CheckTotpWindowSec, thr->lastTotpCode);
}

bool OtpUserTest_IsEqualThrottling(const throttelingS *thr1, const throttelingS *thr2) {
  if (thr1 == NULL || thr2 == NULL) return false;
  if (thr1->lastTotpCode != thr2->lastTotpCode && (thr1->lastTotpCode == NULL || thr2->lastTotpCode == NULL)) return false;
  if (thr1->lastTotpCode != NULL && strcmp(thr1->lastTotpCode, thr2->lastTotpCode) != 0) return false;
  return (thr1->Cliff == thr2->Cliff && thr1->DurationSec == thr2->DurationSec && thr1->throttlingTimerHotp == thr2->throttlingTimerHotp &&
          thr1->throttlingTimerTotp == thr2->throttlingTimerTotp && thr1->CheckHotpWindow == thr2->CheckHotpWindow &&
          thr1->consErrorCounter == thr2->consErrorCounter && thr1->AutoUnblockSec == thr2->AutoUnblockSec &&
          thr1->unblockTimer == thr2->unblockTimer && thr1->CheckTotpWindowSec == thr2->CheckTotpWindowSec);
}

bool OtpUser_IsValid(const OtpUserS *u) {
  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    return false;
  }
  if (u->Throttle->Cliff < MIN_THROTTLING_COUNTER || u->Throttle->Cliff > MAX_THROTTLING_COUNTER) {
    snprintf(errStr, sizeof(errStr), "Error: user struct is not valid, the used throttling counter "
                                     "(%d) is not in the allowed range (%d-%d)",
             (int16_t)u->Throttle->Cliff, (int16_t)MIN_THROTTLING_COUNTER, (int16_t)MAX_THROTTLING_COUNTER);
    return false;
  }
  if (u->Throttle->DurationSec < MIN_THROTTLING_SEC || u->Throttle->DurationSec > MAX_THROTTLING_SEC) {
    snprintf(errStr, sizeof(errStr), "Error: user struct is not valid, the used throttling duration "
                                     "value (%ds) is not in the allowed range (%ds-%ds)",
             (int16_t)u->Throttle->DurationSec, (int16_t)MIN_THROTTLING_SEC, (int16_t)MAX_THROTTLING_SEC);
    return false;
  }
  if (u->Throttle->AutoUnblockSec > MAX_UNBLOCK_SEC) {
    snprintf(errStr, sizeof(errStr), "Error: user struct is not valid, the automatic user unblock is "
                                     "%ds, which is higher than the allowed %ds",
             (int16_t)u->Throttle->AutoUnblockSec, (int16_t)MAX_UNBLOCK_SEC);
    return false;
  }
  if (u->Throttle->CheckHotpWindow < MIN_HOTP_WIDOWS_SIZE || u->Throttle->CheckHotpWindow > MAX_HOTP_WIDOWS_SIZE) {
    snprintf(errStr, sizeof(errStr), "Error: user struct is not valid, the used Hotp check window "
                                     "(%d) is not in the allowed range: %d-%d",
             (int16_t)u->Throttle->CheckHotpWindow, (int16_t)MIN_HOTP_WIDOWS_SIZE, (int16_t)MAX_HOTP_WIDOWS_SIZE);
    return false;
  }
  if (u->Throttle->CheckTotpWindowSec < MIN_TOTP_WIDOWS_SIZE_SEC || u->Throttle->CheckTotpWindowSec > MAX_TOTP_WIDOWS_SIZE_SEC) {
    snprintf(errStr, sizeof(errStr), "Error: user struct is not valid, the used Totp check window in "
                                     "sec (%d) is not in the allowed range: %ds-%ds",
             (int16_t)u->Throttle->CheckTotpWindowSec, (int16_t)MIN_TOTP_WIDOWS_SIZE_SEC, (int16_t)MAX_TOTP_WIDOWS_SIZE_SEC);
    return false;
  }
  if (MAX_THROTTLING_COUNTER - u->Throttle->consErrorCounter < MIN_THROTTLING_COUNTER) {
    snprintf(errStr, sizeof(errStr), "Error: user struct is not valid, the consecutive errors initial "
                                     "value (%d) is larger than maximum allowed - %d",
             (int16_t)u->Throttle->consErrorCounter, (int16_t)MAX_THROTTLING_COUNTER - MIN_THROTTLING_COUNTER);
    return false;
  }
  return true;
}

STATIC void newThrottle(throttelingS **thr, int16_t cliffLen, int16_t durationSec, int16_t autoUnblockSec, int16_t hotpWindowSize, int16_t totpWindowSize) {
  char *str;

  Utils_Malloc((void **)(thr), sizeof(throttelingS));
  (*thr)->Cliff = cliffLen;
  (*thr)->DurationSec = durationSec;
  (*thr)->throttlingTimerHotp = Utils_GetBeginningOfTime();
  (*thr)->throttlingTimerTotp = Utils_GetBeginningOfTime();
  (*thr)->CheckHotpWindow = hotpWindowSize;
  (*thr)->consErrorCounter = DEFAULT_CONS_ERROR_COUNTER;
  (*thr)->AutoUnblockSec = autoUnblockSec;
  (*thr)->unblockTimer = Utils_GetBeginningOfTime();
  (*thr)->CheckTotpWindowSec = totpWindowSize;
  Utils_CreateAndCopyString(&str, LAST_TOTP_CODE_STR, strlen(LAST_TOTP_CODE_STR));
  (*thr)->lastTotpCode = str;
}

STATIC void freeThrottle(throttelingS *thr) {
  if (thr == NULL) return;
  if (thr->lastTotpCode != NULL) Utils_Free(thr->lastTotpCode);
  Utils_Free(thr);
}

// Add a new user if the user is not in the list yet and its parameters are set correctly
// the default parameters are: the user is not blocked, number of errors before blocking:
// defaultThrottlingLen (10), throttling for defaultThrottlingSec (1 sec, 2 sec, 3 sec etc),
// When the user is blocked, it will be automatic unblocked after defaultUnblockSec (3600 sec)
//   The HOTP window size to synchronize between the IoT and the provider is defaultHotpWindowsSize (3)
//   The TOTP window size to handle clock latency between the IoT and the provider is
//   defaultTotpWindowsSizeSec (-30: the IoT Clock can be behind the provider for at most 30 seconds)
//   The HOTP start counter is defaultStartCounter (1000)
bool OtpUser_NewUser(OtpUserS **user, const unsigned char *secret, bool lock, int16_t cliffLen, int16_t thrTimeSec, int16_t autoUnblockSec,
                     int16_t hotpWindowSize, int16_t totpWindowSize, int64_t startCount) {
  Utils_Malloc((void **)(user), sizeof(OtpUserS));
  if (Otp_NewHotp(&((*user)->BaseHotp), secret, startCount) == false) {
    Utils_Free((void *)(*user));
    return false;
  }
  if (Otp_NewTotp(&((*user)->BaseTotp), secret) == false) {
    Otp_FreeHotp((*user)->BaseHotp);
    Utils_Free(user);
    return false;
  }
  EntityManager_RegisterPropertyHandleFunc(OTP_PROPERTY_NAME, OtpUser_FreeUser, OtpUser_Store, OtpUser_Load, OtpUser_PrintUser, OtpUserTest_IsEqual);
  (*user)->Blocked = lock;
  newThrottle(&((*user)->Throttle), cliffLen, thrTimeSec, autoUnblockSec, hotpWindowSize, totpWindowSize);
  return true;
}

void OtpUser_FreeUser(void *u) {
  OtpUserS *user = NULL;

  if (u == NULL) return;
  user = (OtpUserS *)u;
  freeThrottle(user->Throttle);
  user->Throttle = NULL;
  Otp_FreeTotp(user->BaseTotp);
  user->BaseTotp = NULL;
  Otp_FreeHotp(user->BaseHotp);
  user->BaseHotp = NULL;
  Utils_Free(user);
}

bool OtpUser_NewSimpleUser(OtpUserS **user, const unsigned char *secret) {
  return OtpUser_NewUser(user, secret, false, DEFAULT_THROTTLING_LEN, DEFAULT_THROTTLING_SEC, DEFAULT_UNBLOCK_SEC,
                         DEFAULT_HOTP_WINDOWS_SIZE, DEFAULT_TOTP_WINDOWS_SIZE_SEC, DEFAULT_START_COUNTER);
}

bool OtpUser_GetBlockState(const OtpUserS *u) {
  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    return false;
  }
  return u->Blocked;
}

#ifdef STATIC_F // for testing get the automatic unblock timer
STATIC MicroSecTimeStamp getAutoUnBlockedTimer(OtpUserS *u) {
  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return DEFAULT_UNBLOCK_SEC;
  }
  return u->Throttle->unblockTimer;
}
#endif

// set the automatic unblock timer
STATIC bool initAutoUnblockTimer(OtpUserS *u) {
  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  if (u->Throttle->AutoUnblockSec != MANUEL_UNBLOCK_SEC) {
    u->Throttle->unblockTimer = Utils_GetFutureTimeuSec(u->Throttle->AutoUnblockSec);
    MicroSecTimeStamp val = Utils_GetTimeNowInuSec();
    debug_print1("Current time: %ld sec, Set the automatic unblock to %ld", (long int)val, (long int)u->Throttle->unblockTimer);
  }
  return true;
}

bool OtpUser_SetBlockedState(OtpUserS *u, bool val) {
  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    return false;
  }
  u->Blocked = (val == true);
  if (val) return initAutoUnblockTimer(u);
  return true;
}

STATIC bool checkAndUpdateUnBlockStateHelper(OtpUserS *u, int16_t timeOffset) {
  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  if (OtpUser_GetBlockState(u) && u->Throttle->AutoUnblockSec != MANUEL_UNBLOCK_SEC) {
    debug_print1("unblock at %ld, block till %ld\n", (long int)Utils_GetFutureTimeuSec(timeOffset), (long int)u->Throttle->unblockTimer);
    if (Utils_GetFutureTimeuSec(timeOffset) >= u->Throttle->unblockTimer) {
      OtpUser_SetBlockedState(u, false);
      u->Throttle->consErrorCounter = 0; // Is it OK, nothing in the RFC
    }
  }
  return true;
}

// Check if the input code match the expected code in a given window size
// note: the return is true if therewhere no error, if tehrewere no error, the found must be checked
STATIC bool findHotpCodeMatch(OtpUserS *u, const char *code, int16_t size, bool *found, int16_t *match_idx) {
  bool ret = false;
  int16_t i = 0;
  char *calcCode = NULL;

  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  if (code == NULL) {
    snprintf(errStr, sizeof(errStr), "Error: findHotpCodeMatch, verify code wasn't initialized");
    return false;
  }
  *found = false;
  *match_idx = 0;
  for (i = 0; i < size; i++) {
    ret = Otp_GetHotpAtCount(u->BaseHotp, u->BaseHotp->Count + i, &calcCode);
    debug_print1("calc code '%s' compare with '%s', counter %ld\n", calcCode, code, (long int)(u->BaseHotp->Count + i));
    if (ret == false) {
      *found = false;
      return false; // error and not found
    }
    if (strcmp(code, calcCode) == 0) {
      Utils_Free(calcCode);
      *match_idx = i;
      *found = true;
      return true; // no error and found
    }
    Utils_Free(calcCode);
  }
  *found = false;
  return true; // no error but not found
}

// Check if the input code match the expected code in a given window time
// note: the return is true if therewhere no error, if tehrewere no error, the found must be checked
STATIC bool findTotpCodeMatch(OtpUserS *u, const char *code, int16_t timeOffsetSec, bool *found) {
  MicroSecTimeStamp i, start = 0, last = 0, offset = 0;
  char *calcCode = NULL;
  bool ret;

  if (code == NULL || found == NULL) return false;
  *found = false;
  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  offset = timeOffsetSec;
  if (Otp_GetTotpNow(u->BaseTotp, &calcCode) == true) {
    if (strcmp(code, calcCode) == 0) {
      debug_print1("Code '%s' was found with no offset\n", code);
      Utils_Free(calcCode);
      *found = true;
      return true;
    }
  }
  if (offset > 0) {
    start = 1;
    last = offset;
  } else {
    start = offset;
    last = 1;
  }
  Utils_Free(calcCode);
  debug_print1("start %ld last %ld, interval %d\n", (long int)start, (long int)last, (int16_t)u->BaseTotp->Interval);
  for (i = start; i <= last; i += u->BaseTotp->Interval) {
    ret = Otp_GetTotpAtTime(u->BaseTotp, Utils_GetFutureTimeSec(i), &calcCode);
    debug_print1("calc code: '%s', compare with: '%s', offset: %ld, window size: %d, time now in sec %ld, calc time %ld\n", calcCode, code,
                 (long int)i, (int16_t)timeOffsetSec, (long int)Utils_GetFutureTimeSec(0), (long int)Utils_GetFutureTimeSec(i));
    if (ret == false) {
      Utils_Free(calcCode);
      *found = false;
      return false;
    }
    if (strcmp(code, calcCode) == 0) {
      Utils_Free(calcCode);
      *found = true;
      return true;
    }
    Utils_Free(calcCode);
  }
  *found = false;
  return true;
}

STATIC bool handleErrorCode(OtpUserS *u, OtpType otpType) {
  int16_t factor = 1;
  int64_t timer = 0;

  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  if (u->Throttle->consErrorCounter < u->Throttle->Cliff) {
    u->Throttle->consErrorCounter++;
    factor = u->Throttle->consErrorCounter * u->Throttle->DurationSec;
    timer = Utils_GetFutureTimeuSec(factor);
    if (otpType == HOTP_TYPE)
      u->Throttle->throttlingTimerHotp = timer;
    else
      u->Throttle->throttlingTimerTotp = timer;
    debug_print1("Error cnt %d, set throttling timer to %ld, factor %d, add %d sec, Throttle Duration %d Sec\n",
                 (int16_t)u->Throttle->consErrorCounter, (long int)timer, (int16_t)factor, (int16_t)factor, (int16_t)u->Throttle->DurationSec);
    return false;
  }
  OtpUser_SetBlockedState(u, true);
  initAutoUnblockTimer(u);
  snprintf(errStr, sizeof(errStr), "Too many false attempts, locked out");
  debug_print1("Too many false attempts, locked out%s", "\n");
  return false;
}

STATIC bool handleOkCode(OtpUserS *u, const char *code, OtpType otpType, int16_t offset) {
  char *val;

  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  if (code == NULL) return false;
  if (otpType == HOTP_TYPE && offset != 0) {
    u->BaseHotp->Count += offset; // resync the provider interal counter to the client counter
  }
  if (otpType == HOTP_TYPE) {
    u->Throttle->throttlingTimerHotp = Utils_GetBeginningOfTime();
    if (Otp_GetHotpNext(u->BaseHotp, &val) == true) {
      Utils_Free(val);
    }
  } else { // you can't try the code till the next Totp period
    u->Throttle->throttlingTimerTotp = Utils_GetBeginningOfTime();
    if (u->Throttle->lastTotpCode != NULL) {
      Utils_Free(u->Throttle->lastTotpCode);
    }
    Utils_CreateAndCopyString(&val, code, strlen(code));
    u->Throttle->lastTotpCode = val;
  }
  u->Throttle->consErrorCounter = DEFAULT_CONS_ERROR_COUNTER; // clear the consecutive error counter
  return true;
}

STATIC bool isUserBlockedHelper(OtpUserS *user, int16_t offsetTime) {
  if (user == NULL) {
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  if (checkAndUpdateUnBlockStateHelper(user, offsetTime) == false) return false;
  return OtpUser_GetBlockState(user);
}

// OTP shall be verified only if the throttle time is pass and the user is not blocked
STATIC bool canCheckCode(OtpUserS *user, OtpType otpType, int16_t timeFactorSec, bool *canCheck) {
  int64_t cantCheckTill = 0, calcNowTime = 0;
  bool blocked = true;

  *canCheck = false;
  if (user == NULL) {
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  if (otpType == HOTP_TYPE)
    cantCheckTill = user->Throttle->throttlingTimerHotp;
  else
    cantCheckTill = user->Throttle->throttlingTimerTotp;
  calcNowTime = Utils_GetFutureTimeuSec(timeFactorSec);
  debug_print1("Type: %d, timer %ld (%ld), can check only after %ld (%ld), timer factor %d, is OK to check %d\n", (int16_t)otpType,
               (long int)(cantCheckTill / 1000000), (long int)cantCheckTill, (long int)Utils_GetFutureTimeSec(timeFactorSec),
               (long int)Utils_GetFutureTimeuSec(timeFactorSec), (int16_t)timeFactorSec, calcNowTime < cantCheckTill || cantCheckTill == 0);
  if (calcNowTime < cantCheckTill && cantCheckTill != 0) {
    snprintf(errStr, sizeof(errStr), "User must wait %ld Sec before trying again", (long int)((cantCheckTill - calcNowTime + 10000) / 1000000));
    return false;
  }
  blocked = isUserBlockedHelper(user, timeFactorSec);
  if (blocked) {
    snprintf(errStr, sizeof(errStr), "User is blocked, so no check was taken, Please unblock the user first");
    return false;
  }
  *canCheck = true;
  return true;
}

STATIC bool verifyUserCodeHelper(OtpUserS *u, const char *code, OtpType otpType, int16_t timeFactorSec) {
  bool found = false;
  bool ok = false, canCheck = false;
  int16_t offset = 0;

  if (u == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    assert(LIB_NAME "OTP user structure must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  if (code == NULL) return false;
  ok = canCheckCode(u, otpType, timeFactorSec, &canCheck);
  if (ok == false || canCheck == false) {
    return false;
  }
  if (OtpUser_IsValid(u) == false) {
    return false;
  }
  debug_print1("otpType %d, last code '%s', code '%s'\n", otpType, u->Throttle->lastTotpCode, code);
  if (otpType == HOTP_TYPE) {
    ok = findHotpCodeMatch(u, code, u->Throttle->CheckHotpWindow, &found, &offset);
  } else {
    if (u->Throttle->lastTotpCode != NULL && strcmp(u->Throttle->lastTotpCode, code) == 0) { // avoid replay attack for totp
      snprintf(errStr, sizeof(errStr), "Totp Code was already used, you will need to wait for the next time period");
      return false;
    }
    ok = findTotpCodeMatch(u, code, u->Throttle->CheckTotpWindowSec, &found);
  }
  if (ok == false) {
    return false; // error must be checked before return value, to be on the
    // safe side the return is
    // false
  }
  debug_print1("Found code '%s' %d\n", code, found);
  if (found)
    return handleOkCode(u, code, otpType, offset);
  else
    return handleErrorCode(u, otpType);
}

// Verify that the given code is the expected one, if so, increment the internal counter (for hotp)
// or block the same code (for totp)
// The upper layer shell take the action to blocl the user (the upper layer can take more information before blockingthe user)
// the differences between hotp and totp are: the code check and the action if the code was found
bool OtpUser_VerifyCode(OtpUserS *u, const char *code, int16_t otpType) {
  if (u == NULL) return false;
  if (code == NULL) return false;
  return verifyUserCodeHelper(u, code, otpType, 0);
}

bool OtpUser_IsUserBlocked(OtpUserS *user) {
  if (user == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: user stucture wasn't initialized");
    return false;
  }
  return isUserBlockedHelper(user, 0);
}

bool OtpUserTest_IsEqual(const void *u1, const void *u2) {
  const OtpUserS *user1 = NULL, *user2 = NULL;

  if (u1 == NULL || u2 == NULL) return false;
  user1 = (const OtpUserS *)u1;
  user2 = (const OtpUserS *)u2;
  debug_print1("OTPUser: is equal: %d %d %d %d\n", user1->Blocked == user2->Blocked, Otp_IsEqualTotp(user1->BaseTotp, user2->BaseTotp),
               Otp_IsEqualHotp(user1->BaseHotp, user2->BaseHotp), OtpUserTest_IsEqualThrottling(user1->Throttle, user2->Throttle));
  return (user1->Blocked == user2->Blocked && Otp_IsEqualTotp(user1->BaseTotp, user2->BaseTotp) == true &&
          Otp_IsEqualHotp(user1->BaseHotp, user2->BaseHotp) == true && OtpUserTest_IsEqualThrottling(user1->Throttle, user2->Throttle) == true);
}

bool OtpUser_Store(const void *u, const SecureStorageS *storage, const char *prefix) {
  int16_t strLen = MAX_OTP_USER_STR_LEN;
  int16_t prefixLen = 0, mPrefixLen = 0;
  char *otpUserStr = NULL, *key = NULL;
  const OtpUserS *user1 = NULL;

  if (u == NULL || storage == NULL || prefix == NULL) return false;
  prefixLen = strlen(prefix) + strlen(TROTTLING_PREFIX) + 1;
  mPrefixLen = strlen(prefix) + strlen(OTP_MAIN_PREFIX) + 1;
  if (Utils_IsPrefixValid("OtpUser_Store", prefix) == false) return false;
  user1 = (const OtpUserS *)u;
  Utils_Malloc((void **)(&otpUserStr), strLen + 1);
  otpUserStructToStr(user1, otpUserStr, strLen);
  Utils_Malloc((void **)(&key), mPrefixLen);
  snprintf(key, mPrefixLen, OTPUSER_PREFIX_FMT, OTP_MAIN_PREFIX, prefix);
  debug_print1("OtpUser_Store write key '%s' val '%s'\n", key, otpUserStr);
  if (SecureStorage_AddItem(storage, (unsigned char *)key, strlen(key), (unsigned char *)otpUserStr, strlen(otpUserStr)) == false) {
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", prefix, otpUserStr);
    fprintf(stderr, "%s\n", errStr);
    Utils_Free(key);
    Utils_Free(otpUserStr);
    return false;
  }
  Utils_Free(key);
  throttlingStructToStr(user1->Throttle, otpUserStr, strLen);
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, OTPUSER_PREFIX_FMT, TROTTLING_PREFIX, prefix);
  debug_print1("OtpUser_Store write throttling key '%s' val '%s'\n", key, otpUserStr);
  if (SecureStorage_AddItem(storage, (unsigned char *)key, strlen(key), (unsigned char *)otpUserStr, strlen(otpUserStr)) == false) {
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", key, otpUserStr);
    fprintf(stderr, "%s\n", errStr);
    Utils_Free(key);
    Utils_Free(otpUserStr);
    return false;
  }
  Utils_Free(key);
  Utils_Free(otpUserStr);
  if (Otp_StoreHotp(user1->BaseHotp, storage, prefix) == false) return false;
  if (Otp_StoreTotp(user1->BaseTotp, storage, prefix) == false) return false;
  return true;
}

STATIC bool updateThrottleFromStorage(void **user, char *val) {
  int32_t cliffLen, durationSec, consErrorCounter, checkHotpWindow, autoUnblockSec, checkTotpWindow;
  MicroSecTimeStamp throttlingTimerHotp, throttlingTimerTotp, unblockTimer;
  uint32_t throttlingTimerHotp0, throttlingTimerTotp0, unblockTimer0;
  uint32_t throttlingTimerHotp1, throttlingTimerTotp1, unblockTimer1;
  char lastTotpCode[MAX_OTP_USER_STR_LEN];

  if (val == NULL) {
    assert(LIB_NAME "val string must not be NULL" && (false || OtpUser_TestMode));
    return false;
  }
  sscanf(val, THROTTLING_STRUCT_SCAN_FMT, &cliffLen, &durationSec, &throttlingTimerHotp0, &throttlingTimerHotp1, 
    &throttlingTimerTotp0, &throttlingTimerTotp1, &checkHotpWindow, &consErrorCounter, &autoUnblockSec, 
    &unblockTimer0, &unblockTimer1, &checkTotpWindow, lastTotpCode);
  throttlingTimerHotp = (MicroSecTimeStamp) (((uint64_t)throttlingTimerHotp0) << 32) + throttlingTimerHotp1;
  throttlingTimerTotp = (MicroSecTimeStamp) (((uint64_t)throttlingTimerTotp0) << 32) + throttlingTimerTotp1;
  unblockTimer = (MicroSecTimeStamp) (((uint64_t)unblockTimer0) << 32) + unblockTimer1;
  debug_print1("Load throttling data of user%s", "");
  debug_print1(THROTTLING_STRUCT_PRINT_FMT, cliffLen, durationSec, (int32_t)(throttlingTimerHotp >> 32), (int32_t)throttlingTimerHotp, 
    (int32_t)(throttlingTimerTotp >> 32), (int32_t)throttlingTimerTotp, checkHotpWindow, consErrorCounter, autoUnblockSec, 
    (int32_t)(unblockTimer >> 32), (int32_t)unblockTimer, checkTotpWindow, lastTotpCode);
  ((OtpUserS *)*user)->Throttle->Cliff = cliffLen;
  ((OtpUserS *)*user)->Throttle->DurationSec = durationSec;
  ((OtpUserS *)*user)->Throttle->throttlingTimerHotp = throttlingTimerHotp;
  ((OtpUserS *)*user)->Throttle->throttlingTimerTotp = throttlingTimerTotp;
  ((OtpUserS *)*user)->Throttle->CheckHotpWindow = checkHotpWindow;
  ((OtpUserS *)*user)->Throttle->consErrorCounter = consErrorCounter;
  ((OtpUserS *)*user)->Throttle->AutoUnblockSec = autoUnblockSec;
  ((OtpUserS *)*user)->Throttle->unblockTimer = unblockTimer;
  ((OtpUserS *)*user)->Throttle->CheckTotpWindowSec = checkTotpWindow;
  if (((OtpUserS *)*user)->Throttle->lastTotpCode != NULL) Utils_Free(((OtpUserS *)*user)->Throttle->lastTotpCode);
  if (lastTotpCode != NULL) {
    Utils_CreateAndCopyString(&(((OtpUserS *)*user)->Throttle->lastTotpCode), lastTotpCode, strlen(lastTotpCode));
  } else
    ((OtpUserS *)*user)->Throttle->lastTotpCode = NULL;
  return true;
}

bool OtpUser_Load(void **user, const SecureStorageS *storage, const char *prefix, char **retName) {
  bool ret = false, block;
  int16_t prefixLen = 0, mPrefixLen = 0;
  char *val = NULL, *key = NULL;
  unsigned char secret[MAX_SECRET_LEN];

  *retName = NULL;
  if (storage == NULL) {
    snprintf(errStr, sizeof(errStr), "Storage must initiated first");
    return false;
  }
  prefixLen = strlen(prefix) + strlen(TROTTLING_PREFIX) + 1;
  mPrefixLen = strlen(prefix) + strlen(OTP_MAIN_PREFIX) + 1;
  if (Utils_IsPrefixValid("OtpUser_Load", prefix) == false) return false;
  Utils_Malloc((void **)(&key), mPrefixLen);
  snprintf(key, mPrefixLen, OTPUSER_PREFIX_FMT, OTP_MAIN_PREFIX, prefix);
  if (SecureStorage_GetItem(storage, (unsigned char *)key, strlen(key), (unsigned char **)(&val)) == false) {
    snprintf(errStr, sizeof(errStr), "Read from secure storage key '%s' not found", key);
    Utils_Free(key);
    return false;
  }
  debug_print1("read: key: '%s' OtpUser info '%s'\n", key, val);
  Utils_Free(key);
  int tmp;
  sscanf(val, OTP_USER_STRUCT_FMT, secret, &tmp);
  block = tmp;
  Utils_Free(val);
  debug_print1("Load data from OtpUser: %d\n", block);
  if (OtpUser_NewSimpleUser((OtpUserS **)user, secret) == false) {
    return false;
  }
  ((OtpUserS *)*user)->Blocked = block;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, OTPUSER_PREFIX_FMT, TROTTLING_PREFIX, prefix);
  if (SecureStorage_GetItem(storage, (unsigned char *)key, strlen(key), (unsigned char **)(&val)) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: Read from secure storage key '%s' not found", key);
    Utils_Free(key);
    OtpUser_FreeUser((void *)*user);
    return false;
  }
  debug_print1("read: key: '%s' OtpUser info '%s'\n", key, val);
  ret = updateThrottleFromStorage(user, val);
  Utils_Free(key);
  Utils_Free(val);
  if (ret == false) {
    OtpUser_FreeUser((void *)*user);
    return false;
  }
  Otp_FreeHotp(((OtpUserS *)*user)->BaseHotp);
  Otp_FreeTotp(((OtpUserS *)*user)->BaseTotp);
  if (Otp_LoadHotp((void **)(&((OtpUserS *)*user)->BaseHotp), storage, prefix, retName) == false) {
    OtpUser_FreeUser((void *)*user);
    return false;
  }
  if (Otp_LoadTotp((void **)(&((OtpUserS *)*user)->BaseTotp), storage, prefix, retName) == false) {
    OtpUser_FreeUser((void *)*user);
    return false;
  }
  return true;
}
