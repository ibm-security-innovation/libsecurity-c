#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/otp/otp_int.h"
#include "libsecurity/otp/otpUser_int.h"

#define SECRET ((unsigned char *)"12345678901234567890123456789012")
#define NUM_OF_USERS 4

bool OtpTestUser_SetUser(OtpUserS **user, unsigned char *secret);

bool OtpUser_TestUserHOTPCode();
bool OtpUser_TestUserTOTPCode();
bool Test_CheckErrorThrottling();
bool Test_CheckAutomaticUnblockUser();
bool OtpUser_TestStoreLoadUser();
bool OtpUser_TestCorners();

// Test that only legal Otp are created
STATIC bool testOtpCreationCorrectness() {
  int16_t i = 0, offset = 5;
  bool ret = false, pass = true;
  char secret[MAX_SECRET_LEN + offset * 2];
  char *val = NULL;
  OtpS *otp = NULL;

  strcpy(secret, "");
  for (i = 0; i < MAX_SECRET_LEN + offset; i++) {
    ret = Otp_NewAdvance(&otp, (unsigned char *)secret, DEFAULT_NUM_OF_DIGITS, SHA256_FUNC_IDX);
    if (ret == true && (i < MIN_SECRET_LEN || i > MAX_SECRET_LEN)) {
      printf("Test testOtpCreationCorrectness failed: ilegal secret length %d "
             "was exepted\n",
             i);
      pass = false;
    } else if (ret == false && (i >= MIN_SECRET_LEN && i <= MAX_SECRET_LEN)) {
      printf("Test testOtpCreationCorrectness failed: legal secret length %d "
             "was not exepted\n",
             i);
      pass = false;
    }
    if (ret == true) {
      if (Otp_Generate(otp, (int64_t)(i * 100 + 2), &val) == true) Utils_Free(val);
      Otp_Free(otp);
    }
    strcat(secret, "1");
  }
  for (i = 0; i < MAX_NUM_OF_DIGITS + offset; i++) {
    ret = Otp_NewAdvance(&otp, SECRET, i, SHA256_FUNC_IDX);
    if (ret == true && (i < MIN_NUM_OF_DIGITS || i > MAX_NUM_OF_DIGITS)) {
      printf("Test testOtpCreationCorrectness failed: ilegal number of digits "
             "%d was exepted\n",
             i);
      pass = false;
    } else if (ret == false && (i >= MIN_NUM_OF_DIGITS && i <= MAX_NUM_OF_DIGITS)) {
      printf("Test testOtpCreationCorrectness failed: legal number of digits "
             "%d was not exepted\n",
             i);
      pass = false;
    }
    if (ret == true) Otp_Free(otp);
  }
  for (i = 0; i < MAX_DIGEST_IDX + offset; i++) {
    ret = Otp_NewAdvance(&otp, SECRET, DEFAULT_NUM_OF_DIGITS, i);
    if (ret == true && (i < MIN_DIGEST_IDX || i > MAX_DIGEST_IDX)) {
      printf("Test testOtpCreationCorrectness failed: ilegal digest index %d "
             "was exepted\n",
             i);
      pass = false;
    } else if (ret == false && (i >= MIN_DIGEST_IDX && i <= MAX_DIGEST_IDX)) {
      printf("Test testOtpCreationCorrectness failed: legal digest index %d "
             "was not exepted\n",
             i);
      pass = false;
    }
    if (ret == true) Otp_Free(otp);
  }
  return pass;
}

// Test that same OTP are found equal
STATIC bool testOtpAreEqual() {
  int16_t i = 0, len = 4;
  bool ret = false, pass = true;
  OtpS *otp1 = NULL, *otp2 = NULL;

  Otp_NewAdvance(&otp1, SECRET, DEFAULT_NUM_OF_DIGITS, SHA256_FUNC_IDX);
  Otp_NewAdvance(&otp2, SECRET, DEFAULT_NUM_OF_DIGITS, SHA256_FUNC_IDX);
  for (i = 0; i < len; i++) {
    if (i == 1)
      otp1->Digits = otp1->Digits + 1;
    else if (i == 2)
      otp1->DigestType = otp1->DigestType + 1;
    else if (i == 3)
      Otp_ReplaceSecret(otp1, (unsigned char *)"lalalala");
    ret = Otp_IsEqual(otp1, otp2);
    if ((ret == true && i > 0) || (ret == false && i == 0)) {
      if (i > 0)
        printf("Test testOtpAreEqual failed: different otp was found equal\n");
      else
        printf("Test testOtpAreEqual failed: same otp was not equal\n");
      Otp_Print(stdout, "Otp1\n", otp1);
      Otp_Print(stdout, "Otp2\n", otp2);
      pass = false;
    }
    Otp_Free(otp1);
    Otp_NewAdvance(&otp1, SECRET, DEFAULT_NUM_OF_DIGITS, SHA256_FUNC_IDX);
  }
  Otp_Free(otp1);
  Otp_Free(otp2);
  return pass;
}

// Verify that next give the same value as at count and is not equal to the old
// value
// Verify that different counters results with different OTP values
// Verify that 2 random OTP give 2 different values
STATIC bool testHotpNextAtCount() {
  int16_t i = 0, j = 0, len = 100, size = 5;
  bool pass = true, res = false;
  HotpS *refHotp, *hotp;
  char *val, *val1;
  char lastVal[MAX_NUM_OF_DIGITS];
  int64_t count = 100;

  if (Otp_NewHotp(&refHotp, SECRET, count - 1) == false) {
    printf("Can't run testHotpNext, Error: %s\n", errStr);
    return false;
  }
  Otp_NewHotp(&hotp, SECRET, count - 1);
  for (i = 0; i < len; i++) {
    if (Otp_GetHotpNext(refHotp, &val) == true) {
      for (j = i - size; j < i + size; j++) {
        Otp_GetHotpAtCount(hotp, j + count, &val1);
        res = strcmp(val, val1);
        if (res != 0 && i == j) {
          printf("Test testHotpNextAtCount failed: OTP for the same counter %ld yield to diffrent results %s, %s\n",
                 (long int)(i + count), val, val1);
          pass = false;
        } else if (res == 0 && i != j) {
          printf("Test testHotpNextAtCount failed: OTP with different counters %ld, %ld yield to the same results %s, %s\n",
                 (long int)(i + count), (long int)(j + count), val, val1);
          pass = false;
        }
        Utils_Free(val1);
      }
      if (i > 0) {
        if (strcmp(val, lastVal) == 0) {
          printf("Test testHotpNextAtCount failed: OTP for the different counters %ld, %ld yield to the same results %s, %s\n",
                 (long int)(i + count - 1), (long int)(i + count), val, lastVal);
          pass = false;
        }
      }
      strncpy(lastVal, val, MAX_NUM_OF_DIGITS);
      Utils_Free(val);
    } else
      pass = false;
    if (Otp_HotpRandom(hotp, &val) == true) {
      Otp_HotpRandom(hotp, &val1);
      if (strcmp(val, val1) == 0) {
        printf("Test testHotpNextAtCount failed: 2 random OTP give the same result: %s, %s\n", val, val1);
        pass = false;
      }
      Utils_Free(val);
      Utils_Free(val1);
    } else
      pass = false;
  }
  Otp_FreeHotp(refHotp);
  Otp_FreeHotp(hotp);
  return pass;
}

STATIC bool testTotpNowAtTime() {
  int16_t i = 0, j = 0, len = 6, delta = 0, size = 0;
  bool res = false, pass = true, done = false;
  TotpS *refTotp, *totp;
  char *val, *val1;
  char lastVal[MAX_NUM_OF_DIGITS];
  int64_t timeNow = 0;

  if (Otp_NewTotp(&refTotp, SECRET) == false) {
    printf("Can't run testTotpNext, Error: %s\n", errStr);
    return false;
  }
  Otp_NewTotp(&totp, SECRET);

  for (delta = 0; delta < DEFAULT_INTERVAL_SEC * 6; delta += DEFAULT_INTERVAL_SEC * 1.5) {
    size = 5 * delta;
    for (i = 0; i < len * delta; i += delta) {
      timeNow = (Utils_GetTimeNowInSec() / totp->Interval) * totp->Interval;
      if (Otp_GetTotpAtTime(totp, timeNow + i, &val) == true) {
        if (i == 0 && done == false) {
          Otp_GetTotpNow(refTotp, &val1);
          if (strcmp(val, val1) != 0) {
            printf("Test testTotpNowAtTime failed: TOTP for the same time %ld "
                   "yield to diffrent "
                   "results %s, %s\n",
                   (long int)(i + timeNow), val, val1);
            pass = false;
          }
          done = true;
          Utils_Free(val1);
        }
        for (j = i; j < i + size; j += delta) {
          Otp_GetTotpAtTime(totp, j + timeNow, &val1);
          res = strcmp(val, val1);
          if (res != 0 && i < j && abs(i - j) <= DEFAULT_INTERVAL_SEC / 2) {
            printf("Test testTotpNowAtTime failed: TOTP for time with the same "
                   "windows size %ld, "
                   "%ld (%d) yield to diffrent results %s, %s\n",
                   (long int)(i + timeNow), (long int)(j + timeNow), abs(i - j), val, val1);
            pass = false;
          } else if (res == 0 && i < j && abs(i - j) > DEFAULT_INTERVAL_SEC / 2) {
            printf("Test testTotpNowAtTime failed: TOTP with different time "
                   "%ld, %ld yield to the "
                   "same results %s, %s (diff time %d, window size %d)\n",
                   (long int)(i + timeNow), (long int)(j + timeNow), val, val1, abs(i - j), DEFAULT_INTERVAL_SEC);
            pass = false;
          }
          Utils_Free(val1);
        }
        if (i > 0) {
          if (strcmp(val, lastVal) == 0) {
            printf("Test testTotpNowAtTime failed: TOTP for different time "
                   "%ld, %ld yield to the "
                   "same results %s, %s\n",
                   (long int)(timeNow + i - delta), (long int)(timeNow + i), val, lastVal);
            pass = false;
          }
        }
        strncpy(lastVal, val, MAX_NUM_OF_DIGITS);
        Utils_Free(val);
      } else
        pass = false;
    }
  }
  Otp_FreeTotp(refTotp);
  Otp_FreeTotp(totp);
  return pass;
}

STATIC bool testOtpCorners() {
  int i;
  bool pass = true;
  OtpS *otp = NULL, *otp1 = NULL;
  char key[crypto_auth_BYTES + 2];

  Otp_New(&otp, SECRET);
  Otp_New(&otp1, SECRET);
  for (i = 0; i < crypto_auth_BYTES; i++)
    key[i] = '1';
  key[crypto_auth_BYTES + 1] = 0;
  Utils_Free(otp1->Secret);
  otp1->Secret = NULL;
  if (generateHmac(otp, "abc", NULL) == true || generateHmac(otp1, key, NULL) == true || Otp_New(&otp, NULL) == true ||
      timeCode(NULL, 1) != 1 || Otp_IsEqual(otp, otp1) == true || isValidInterval(MIN_INTERVAL_SEC - 1) == true) {
    printf("testOtpCorners failed, function with invalid parameters retured true\n");
    pass = false;
  }
  Otp_Free(otp);
  Otp_Free(otp1);
  return pass;
}

#ifdef MBED_OS
int16_t testOtp()
#else
int32_t main()
#endif
{
  bool pass = true;
  int16_t i, len = 0;
  char *res;

  Otp_TestMode = true;
  OtpUser_TestMode = true;

  Utils_TestFuncS callFunc[] = { 
                                 { "testOtpCreationCorrectness", testOtpCreationCorrectness },
                                 { "testOtpAreEqual", testOtpAreEqual },
                                 { "testHotpNextAtCount", testHotpNextAtCount },
                                 { "testTotpNowAtTime", testTotpNowAtTime },
                                 { "OtpUser_TestUserHOTPCode", OtpUser_TestUserHOTPCode },
                                 { "OtpUser_TestUserTOTPCode", OtpUser_TestUserTOTPCode },
                                 { "Test_CheckErrorThrottling", Test_CheckErrorThrottling },
                                 { "OtpUser_TestStoreLoadUser", OtpUser_TestStoreLoadUser },
                                 { "Test_CheckAutomaticUnblockUser", Test_CheckAutomaticUnblockUser },
                                 { "OtpUser_TestCorners", OtpUser_TestCorners },
                                 { "testOtpCorners", testOtpCorners } 
                                };

  len = sizeof(callFunc) / sizeof(Utils_TestFuncS);
  for (i = 0; i < len; i++) {
    if ((callFunc[i]).testFunc() == false) {
      res = "fail";
      pass = false;
    } else
      res = "pass";
    printf("Test %s:'%s' %s\n", __FILE__, callFunc[i].name, res);
  }
  EntityManager_RemoveRegisteredPropertyList();
  return pass;
}
