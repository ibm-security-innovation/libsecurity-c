#include "example.h"

static const unsigned char *OtpSecret = ((const unsigned char *)"a12T3998767");

static bool verifyCodeHotp(OtpUserS *otpUser, int16_t codeOffset, bool isMatchExpected) {
  bool ret = false;
  char *val1 = NULL;

  if (Otp_GetHotpAtCount(otpUser->BaseHotp, otpUser->BaseHotp->Count + codeOffset, &val1) == false) {
    printf("verifyCodeHotp failed, can't calulate expected code, error: %s\n", errStr);
    return false;
  }
  ret = OtpUser_VerifyCode(otpUser, val1, HOTP_TYPE);
  if (ret) {
    if (isMatchExpected) {
      printf("verifyCodeHotp code '%s' (offset %d, max offset %d) matched as expected\n", val1, codeOffset, otpUser->Throttle->CheckHotpWindow);
    }else {
      printf("verifyCodeHotp failed, code '%s' matched but it was not expected to match (offset %d > max offset %d)\n", val1, codeOffset, otpUser->Throttle->CheckHotpWindow);
      Utils_Free(val1);
      return false;
    }
  }else {
    if (isMatchExpected) {
      printf("verifyCodeHotp failed, code didn't match as expected, expected: user code %s, offset %d\n", val1, codeOffset);
      Utils_Free(val1);
      return false;
    }else {
      printf("verifyCodeHotp code '%s' (offset %d, max offset %d) did not match, as expected\n", val1, codeOffset, otpUser->Throttle->CheckHotpWindow);
    }
  }
  Utils_Free(val1);
  return true;
}

static bool verifyCodeTotp(OtpUserS *otpUser, bool isMatchExpected) {
  bool ret = false;
  char *val1 = NULL;

  if (Otp_GetTotpNow(otpUser->BaseTotp, &val1) == false) {
    printf("verifyCodeTotp failed, can't calulate expected code, Error: %s\n", errStr);
    return false;
  }
  ret = OtpUser_VerifyCode(otpUser, val1, TOTP_TYPE);
  if (ret) {
    if (isMatchExpected) {
      printf("verifyCodeTotp, code matched as expected, expected: user code %s\n", val1);
    }else {
      printf("verifyCodeHotp failed, code '%s' matched but was not expected to match (it is the same as the old matched code)\n", val1);
      Utils_Free(val1);
      return false;
    }
  }else {
    if (isMatchExpected) {
      printf("verifyCodeTotp failed, code '%s' did not match\n", val1);
      Utils_Free(val1);
      return false;
    }else {
      printf("verifyCodeHotp code '%s' did not match, as expected (it is equal to the previous code)\n", val1);
    }
  }
  Utils_Free(val1);
  return true;
}

static bool checkOtp(EntityManager *entityManager, const char *userName) {
  bool pass=true;
  OtpUserS *otpUser;

  if (EntityManager_GetProperty(entityManager, userName, OTP_PROPERTY_NAME, (void **)&otpUser) == false) {
    printf("checkOtp failed, can't get user '%s' OTP property, Error: %s\n", userName, errStr);
    return false;
  }
  pass = pass && verifyCodeHotp(otpUser, 0, true);
  pass = pass && verifyCodeHotp(otpUser, otpUser->Throttle->CheckHotpWindow-1, true);
  pass = pass && verifyCodeHotp(otpUser, otpUser->Throttle->CheckHotpWindow+1, false);
  pass = pass && verifyCodeTotp(otpUser, true);
  pass = pass && verifyCodeTotp(otpUser, false);
  return pass;
}

static bool createAndAddOtp(EntityManager *entityManager, const char *userName) {
  OtpUserS *otpUser;

  if (OtpUser_NewSimpleUser(&otpUser, OtpSecret) == false) {
    printf("createAndAddOtp failed, Can't create OTP user, error: %s\n", errStr);
    return false;
  }
  return EntityManager_RegisterProperty(entityManager, userName, OTP_PROPERTY_NAME, (void *)otpUser);
}

bool AddOtp(EntityManager *entityManager, int16_t userId) {
  bool pass = true;
  char userName[EXP_MAX_USER_NAME];

  snprintf(userName, sizeof(userName), USER_NAME_FMT, userId);
  pass = createAndAddOtp(entityManager, userName);
  if (pass) {
    pass = checkOtp(entityManager, userName);
  }
  return pass;
}
