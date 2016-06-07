// #include "test_otp.h"

#include "libsecurity/otp/otp_int.h"
#include "libsecurity/otp/otpUser_int.h"

#define SECRET ((unsigned char *)"12345678901234567890123456789012")
#define SALT ((unsigned char *)"salt-a1b2c3d")
#define NUM_OF_USERS 4
#define OTHER_SECRET "12345678"

bool OtpTestUser_SetUser(OtpUserS **user, unsigned char *secret) {
  unsigned char *secret1, *secret2;
  char *lastPwdPtr;
  unsigned char fixedSecret[crypto_auth_BYTES + 1];

  if (OtpUser_NewSimpleUser(user, secret) == false) return false;
  (*user)->Throttle->Cliff = 11;
  (*user)->Throttle->DurationSec = 2;
  (*user)->Throttle->throttlingTimerHotp = 3;
  (*user)->Throttle->throttlingTimerTotp = 4;
  (*user)->Throttle->CheckHotpWindow = 5;
  (*user)->Throttle->consErrorCounter = 6;
  (*user)->Throttle->AutoUnblockSec = 7;
  (*user)->Throttle->unblockTimer = 8;
  (*user)->Throttle->CheckTotpWindowSec = 9;
  if ((*user)->Throttle->lastTotpCode != NULL) Utils_Free((*user)->Throttle->lastTotpCode);
  Utils_CreateAndCopyString(&lastPwdPtr, "lalala", strlen("lalala"));
  (*user)->Throttle->lastTotpCode = lastPwdPtr;
  (*user)->Blocked = true;
  (*user)->BaseHotp->Count = 1;
  Utils_Free((*user)->BaseHotp->BaseOtp->Secret);
  setSecretStr(fixedSecret, (unsigned char *)OTHER_SECRET);
  Utils_CreateAndCopyUcString(&secret1, fixedSecret, strlen((char *)fixedSecret));
  (*user)->BaseHotp->BaseOtp->Secret = secret1;
  (*user)->BaseHotp->BaseOtp->Digits = 8;
  (*user)->BaseHotp->BaseOtp->DigestType = 0;
  (*user)->BaseTotp->Interval = 12;
  Utils_Free((*user)->BaseTotp->BaseOtp->Secret);
  setSecretStr(fixedSecret, (unsigned char *)OTHER_SECRET);
  Utils_CreateAndCopyUcString(&secret2, fixedSecret, strlen((char *)fixedSecret));
  (*user)->BaseTotp->BaseOtp->Secret = secret2;
  (*user)->BaseTotp->BaseOtp->Digits = 9;
  (*user)->BaseTotp->BaseOtp->DigestType = 1;
  return true;
}

// verify that wrong codes will not match
// verify that the relevant code match (if it is the search window size and that
// it will sync)
bool OtpUser_TestUserHOTPCode() {
  int16_t i = 0, u = 0, ret, len = 3;
  bool pass = true;
  int16_t hotpWindowSize[NUM_OF_USERS] = { 3, 3, 3, 2 };
  int16_t offset[NUM_OF_USERS] = { -1, 4, -1, -1 };
  bool expected[NUM_OF_USERS] = { true, false, true, true };
  OtpUserS *user[NUM_OF_USERS];
  int64_t startCount = 100;
  char *val1 = NULL;

  // user1 is sync with the cuonter, user2, is not sync and couldn't sync, user3
  // and user4 must sync
  // after the first match
  for (i = 0; i < NUM_OF_USERS; i++) {
    if (OtpUser_NewUser(&(user[i]), SECRET, false, 600, 5, 400, hotpWindowSize[i], 200, startCount + offset[i]) == false) {
      printf("OtpUser_TestUserHOTPCode failed, Can't create user, Error: %s\n", errStr);
      return false;
    }
  }
  for (u = 0; u < NUM_OF_USERS; u++) {
    if (OtpUser_VerifyCode(user[u], OTHER_SECRET, HOTP_TYPE) == true) {
      printf("OtpUser_TestUserHOTPCode failed, wrong code was excepted, Error: "
             "%s\n",
             errStr);
      pass = false;
    }
    for (i = 0; i < len; i++) {
      if (Otp_GetHotpAtCount((user[u])->BaseHotp, startCount + i, &val1) == false) {
        printf("OtpUser_TestUserHOTPCode failed, can't calulate expected code, "
               "Error: %s\n",
               errStr);
        pass = false;
      }
      ret = verifyUserCodeHelper(user[u], val1, HOTP_TYPE, user[u]->Throttle->DurationSec);
      if (ret == false && expected[u] == true) {
        printf("OtpUser_TestUserHOTPCode failed, code wasn't match as expected, index %d, expected: user code %s, ret %d, Error: %s\n",
               i, val1, ret, errStr);
        pass = false;
      } else if (ret == true && expected[u] == false) {
        printf("OtpUser_TestUserHOTPCode failed, user code %s was matched unexpectedly, index %d\n", val1, i);
        pass = false;
      }
      Utils_Free(val1);
    }
  }
  for (u = 0; u < NUM_OF_USERS; u++)
    OtpUser_FreeUser(user[u]);
  return pass;
}

// Check that the throttling counter delay count as expected (2^num of
// unsuccessfull retries)
// and the next time the code is checked is after the throttling time pass
bool Test_CheckErrorThrottling() {
  int16_t i = 0, factor = 0;
  bool ret = false, pass = true;
  OtpUserS *user;
  int16_t throttleTimeSec = 2, cliff = 10;
  char *val = NULL;
  int64_t startCounter = 1000, expected = 0;

  if (OtpUser_NewUser(&user, SECRET, false, cliff, throttleTimeSec, 400, 1, 200, startCounter) == false) {
    printf("Test_CheckErrorThrottling failed, Can't create user, Error: %s\n", errStr);
    return false;
  }
  for (i = 0; i < 10; i++) {
    OtpUser_SetBlockedState(user, false);
    factor = (i + 1) * throttleTimeSec;
    verifyUserCodeHelper(user, OTHER_SECRET, HOTP_TYPE, factor); // error codes to increase the delay
    expected = Utils_GetFutureTimeuSec(factor);
    if (user->Throttle->throttlingTimerHotp > expected) {
      printf("Test_CheckErrorThrottling failed, expected the throttle value to be lower than %ld, "
             "but the return throttling value was %ld, factor is %d\n",
             (long int)expected, (long int)user->Throttle->throttlingTimerHotp, (int16_t)factor);
      pass = false;
    }
    if (i == 0) { // check that the throttling timer work OK for the basic unit
      if (Otp_GetHotpAtCount(user->BaseHotp, startCounter, &val) == false) {
        printf("Test_CheckErrorThrottling failed, can't calulate expected code, Error: %s\n", errStr);
        pass = false;
        break;
      }
      if (OtpUser_VerifyCode(user, val, HOTP_TYPE) == true) { // test should not be checked before throttling duration
        printf("Test_CheckErrorThrottling failed, OTP should not be checked before: %d seconds\n", factor);
        pass = false;
        ret = verifyUserCodeHelper(user, val, HOTP_TYPE, factor);
        if (ret == false) {
          printf("Test_CheckErrorThrottling failed, expected to be throttle for: %ds, checked after %ds, error: %s\n",
                 (int16_t)throttleTimeSec, (int16_t)factor, errStr);
          pass = false;
        }
        if (ret == true) { // advance the internal counter
          user->BaseHotp->Count = user->BaseHotp->Count + 1;
        }
        if (pass == false) {
          Utils_Free(val);
          break;
        }
      }
      Utils_Free(val);
    }
  }
  OtpUser_FreeUser(user);
  return pass;
}

// Check that when the user is locked out, after predefined delay it is
// automatically unblocked
bool Test_CheckAutomaticUnblockUser() {
  int16_t len = 2, offsetsSec[2] = { -2, 0 }; // must be the same as len
  int16_t i = 0;
  bool pass = true, blocked = true, ret = false;
  OtpUserS *user;
  int16_t throttleTimeSec = 2, cliff = 10;
  char *val = NULL;
  int64_t startCounter = 1000, expected = 0;

  if (OtpUser_NewUser(&user, SECRET, false, cliff, throttleTimeSec, 400, 1, 200, startCounter) == false) {
    printf("Test_CheckAutomaticUnblockUser failed, Can't create user, Error: %s\n", errStr);
    OtpUser_FreeUser(user);
    return false;
  }
  user->Throttle->AutoUnblockSec = DEFAULT_UNBLOCK_SEC;
  for (i = 0; i < user->Throttle->Cliff + 1; i++) {
    if (verifyUserCodeHelper(user, OTHER_SECRET, HOTP_TYPE, 100) == true) {
      printf("Test_CheckAutomaticUnblockUser failed, wrong code was exepted\n");
      pass = false;
    }
  }
  if (OtpUser_GetBlockState(user) == false) {
    printf("Test_CheckAutomaticUnblockUser failed, user must be blocked after %d wrong tries\n",
           (int16_t)user->Throttle->Cliff);
    OtpUser_FreeUser(user);
    return false;
  }
  expected = Utils_GetFutureTimeuSec(user->Throttle->AutoUnblockSec);
  if (getAutoUnBlockedTimer(user) > expected) {
    printf("Test_CheckAutomaticUnblockUser fail, expected the throttle value to be till: %ld, but "
           "the return throttling value was %ld\n", (long int)expected, (long int)getAutoUnBlockedTimer(user));
  } else {
    for (i = 0; i < len; i++) {
      Otp_GetHotpAtCount(user->BaseHotp, startCounter, &val);
      ret = verifyUserCodeHelper(user, val, HOTP_TYPE, user->Throttle->AutoUnblockSec + offsetsSec[i]);
      blocked = OtpUser_GetBlockState(user);
      if (blocked == false && offsetsSec[i] < 0) {
        printf("Test_CheckAutomaticUnblockUser failed, code match %d, user must not be "
               "automatically unblocked before %d seconds, but it was unblocked after %d sec\n",
               (int16_t)ret, (int16_t)user->Throttle->AutoUnblockSec, (int16_t)user->Throttle->AutoUnblockSec + offsetsSec[i]);
        pass = false;
      } else if (blocked == true && offsetsSec[i] >= 0) {
        printf("Test_CheckAutomaticUnblockUser failed, code match %d, user must be automatically "
               "unblocked after %d seconds, time pass since blocked %d sec\n",
               (int16_t)ret, (int16_t)user->Throttle->AutoUnblockSec, (int16_t)user->Throttle->AutoUnblockSec + offsetsSec[i]);
        pass = false;
      }
      Utils_Free(val);
    }
  }
  OtpUser_FreeUser(user);
  return pass;
}

// verify that wrong codes will not match
// verify that the relevant code match (if it is the search window size)
// verify that the same code could not be used twich (need to wait for next
// interval)
bool OtpUser_TestUserTOTPCode() {
  int16_t u = 0, ret;
  bool pass = true;
  int16_t totpWindowSizeSec[NUM_OF_USERS] = { 30, 1, 60, -30 };
  int16_t offsetSec[NUM_OF_USERS] = { 1, 34, -10, -10 };
  // all are for interval of 30 sec offset 1 should pass, offset 34 with window size of 1 should fail, offset
  // -20 with positive window size should fail and offset -10 with window -30 should pass
  bool expected[NUM_OF_USERS] = { true, false, false, true };
  OtpUserS *user[NUM_OF_USERS];
  int64_t timeSec = 0;
  char *val1 = NULL;

  // user1 is sync with the cuonter, user2, is not sync and couldn't sync, user3 and user4 must sync after the first match
  for (u = 0; u < NUM_OF_USERS; u++) {
    if (OtpUser_NewUser(&(user[u]), SECRET, false, 600, 5, 400, 3, totpWindowSizeSec[u], 100) == false) {
      printf("OtpUser_TestUserTOTPCode failed, Can't create user, Error: %s\n", errStr);
      return false;
    }
  }
  for (u = 0; u < NUM_OF_USERS; u++) {
    if (OtpUser_VerifyCode(user[u], OTHER_SECRET, TOTP_TYPE) == true) {
      printf("OtpUser_TestUserTOTPCode failed, wrong code was excepted, Error: "
             "%s\n",
             errStr);
      pass = false;
    }
    timeSec = ((Utils_GetTimeNowInSec() / (user[u])->BaseTotp->Interval) * (user[u])->BaseTotp->Interval + offsetSec[u]);
    if (Otp_GetTotpAtTime((user[0])->BaseTotp, timeSec, &val1) == false) {
      printf("OtpUser_TestUserTOTPCode failed, can't calulate expected code, Error: %s\n", errStr);
      pass = false;
    }
    ret = verifyUserCodeHelper(user[u], val1, TOTP_TYPE, user[u]->Throttle->DurationSec);
    if (ret == false && expected[u] == true) {
      printf("OtpUser_TestUserTOTPCode failed, code wasn't match as expected, index %d, expected: user code %s, ret %d, Error: %s\n",
             u, val1, ret, errStr);
      pass = false;
    } else if (ret == true && expected[u] == false) {
      printf("OtpUser_TestUserTOTPCode failed, user code %s was matched unexpectedly, index %d\n", val1, u);
      pass = false;
    }
    if (ret == true && OtpUser_VerifyCode(user[u], val1, TOTP_TYPE) == true) {
      printf("OtpUser_TestUserTOTPCode failed, The same code %s was matched twice, index %d\n", val1, u);
      pass = false;
    }
    Utils_Free(val1);
  }
  for (u = 0; u < NUM_OF_USERS; u++)
    OtpUser_FreeUser(user[u]);
  return pass;
}

bool OtpUser_TestStoreLoadUser() {
  bool pass = true;
  OtpUserS *user3 = NULL, *user4 = NULL;
  SecureStorageS storage;
  char *fileName = "tmp.txt", *tName = NULL;

  if (SecureStorage_NewStorage((unsigned char *)SECRET, (unsigned char *)SALT, &storage) == false) {
    printf("testStoreLoadUser failed, Can't create new storage, Error: %s\n", errStr);
    return false;
  }
  OtpTestUser_SetUser(&user3, SECRET);
  OtpUser_Store(user3, &storage, "u1");
  if (OtpUser_Load((void **)&user4, &storage, "u1", &tName) == true) {
    Utils_Free(tName);
  }
  if (OtpUserTest_IsEqual(user3, user4) == false) {
    printf("testStoreLoadUser failed, stored user != loaded one\n");
    OtpUser_PrintUser(stdout, "Original user:\n", user3);
    OtpUser_PrintUser(stdout, "Loaded user:\n", user4);
    pass = false;
  }
#ifndef MBED_OS
  FILE *devNull = fopen("/dev/null", "w");
  OtpUser_PrintUser(devNull, "test print: ", (void *)user3);
  fclose(devNull);
#endif
  SecureStorage_FreeStorage(&storage);
  OtpUser_FreeUser(user3);
  OtpUser_FreeUser(user4);
  remove(fileName);
  return pass;
}

bool OtpUser_TestCorners() {
  int i = 0, oldVal;
  int val[] = { MIN_THROTTLING_COUNTER - 1,   MIN_THROTTLING_SEC - 1,     MAX_UNBLOCK_SEC + 1, MIN_HOTP_WIDOWS_SIZE - 1,
                MIN_TOTP_WIDOWS_SIZE_SEC - 1, MAX_THROTTLING_COUNTER - 1, 0 };
  bool pass = true, tmp;
  OtpUserS *user = NULL;

  if (OtpUser_NewSimpleUser(&user, NULL) == true || OtpUser_GetBlockState(NULL) == true || getAutoUnBlockedTimer(NULL) == true ||
      initAutoUnblockTimer(NULL) == true || OtpUser_SetBlockedState(NULL, true) == true || findHotpCodeMatch(NULL, OTHER_SECRET, 1, NULL, NULL) == true ||
      findHotpCodeMatch(user, NULL, 1, NULL, NULL) == true || findTotpCodeMatch(NULL, NULL, 1, NULL) == true ||
      findTotpCodeMatch(NULL, OTHER_SECRET, 1, &tmp) == true || handleErrorCode(NULL, 1) == true || handleOkCode(NULL, NULL, 1, 1) == true ||
      verifyUserCodeHelper(NULL, NULL, 1, 1) == true || OtpUser_VerifyCode(NULL, NULL, 1) == true || OtpUser_IsUserBlocked(NULL) == true) {
    printf("OtpUser_TestCorners failed, function with NULL parameters retured true\n");
    pass = false;
  }
  OtpTestUser_SetUser(&user, SECRET);
  for (i = 0; i < 7; i++) {
    switch (i) {
      case 0:
        oldVal = user->Throttle->Cliff;
        user->Throttle->Cliff = val[i];
        break;
      case 1:
        user->Throttle->Cliff = oldVal;
        oldVal = user->Throttle->DurationSec;
        user->Throttle->DurationSec = val[i];
        break;
      case 2:
        user->Throttle->DurationSec = oldVal;
        oldVal = user->Throttle->AutoUnblockSec;
        user->Throttle->AutoUnblockSec = val[i];
        break;
      case 3:
        user->Throttle->AutoUnblockSec = oldVal;
        oldVal = user->Throttle->CheckHotpWindow;
        user->Throttle->CheckHotpWindow = val[i];
        break;
      case 4:
        user->Throttle->CheckHotpWindow = oldVal;
        oldVal = user->Throttle->CheckTotpWindowSec;
        user->Throttle->CheckTotpWindowSec = val[i];
        break;
      case 5:
        user->Throttle->CheckTotpWindowSec = oldVal;
        oldVal = user->Throttle->consErrorCounter;
        user->Throttle->consErrorCounter = val[i];
        break;
      case 6:
        OtpUser_FreeUser(user);
        user = NULL;
        break;
    }
    if (OtpUser_IsValid(user) == true) {
      printf("OtpUser_Test_CheckAutomaticUnblockUserners failed, OtpUser_IsValid with wrong parameter %d retured true\n", i);
      pass = false;
    }
  }
  OtpUser_FreeUser(user);
  return pass;
}