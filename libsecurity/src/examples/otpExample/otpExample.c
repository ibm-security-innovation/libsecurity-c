#include "otpExample.h"
#include "waterMeter.h"

static bool addUsersAndResource(EntityManager *entityManager, const char *usersList[], int len, const char *resourceName) {
  int16_t i=0;

  for (i=0 ; i<len ; i++) {
    if (EntityManager_AddUser(entityManager, usersList[i]) == false) {
      printf("Error: Can't add user '%s' to the entity manager, error: %s\n", usersList[i], errStr);
      return false;
    }
  }
  if (EntityManager_AddResource(entityManager, resourceName) == false) {
    printf("Error: Can't add resource '%s' to the entity manager, error: %s\n", resourceName, errStr);
    return false;
  }
  return true;
}

static bool addPermission(EntityManager *entityManager, const char *resourceName, const char *userName, const char *permission) {
  Acl_AddPermissionToResource(entityManager, resourceName, userName, permission);
  return true;
}

static bool createAndAddOtpToResource(EntityManager *entityManager, const char *resourceName, const unsigned char *otpSecret) {
  OtpUserS *otpUser;

  if (OtpUser_NewSimpleUser(&otpUser, otpSecret) == false) {
    printf("createAndAddOtpToResource failed, Can't create OTP, error: %s\n", errStr);
    return false;
  }
  return EntityManager_RegisterProperty(entityManager, resourceName, OTP_PROPERTY_NAME, (void *)otpUser);
}

// On success, both the internal OTP and the water meter counters must increase by the same counter delta, it is done using verify code
static bool syncOtpCounters(EntityManager *entityManager, const char *resourceName, const char *otpVal) {
  OtpUserS *otpData;

  if (EntityManager_GetProperty(entityManager, resourceName, OTP_PROPERTY_NAME, (void **)&otpData) == false) {
    printf("calcExpectedOtpOfWaterMeter failed, can't get user '%s' OTP property, Error: %s\n", resourceName, errStr);
    return false;
  }
  return OtpUser_VerifyCode(otpData, otpVal, HOTP_TYPE);
}

static bool calcExpectedOtpOfWaterMeter(EntityManager *entityManager, const char *userName, const char *resourceName, const char *requiredPrrmission, OtpType type, char **otpVal) {
  bool res = false;
  OtpUserS *otpUser;

  // Check if user has permission for resource
  if (Acl_CheckEntityPermission(entityManager, resourceName, userName, requiredPrrmission) == false) {
    printf("calcExpectedOtpOfWaterMeter: User '%s' doesn't have permission '%s' for resource '%s'\n", userName, requiredPrrmission, resourceName);
    return false;
  }
  if (EntityManager_GetProperty(entityManager, resourceName, OTP_PROPERTY_NAME, (void **)&otpUser) == false) {
    printf("calcExpectedOtpOfWaterMeter failed, can't get user '%s' OTP property, Error: %s\n", resourceName, errStr);
    return false;
  }
  // Calculate the expected OTP value for resource (HOTP or TOTP)
  if (type == HOTP_TYPE) {
    res = Otp_GetHotpAtCount(otpUser->BaseHotp, otpUser->BaseHotp->Count, otpVal);
  }else {
    res = Otp_GetTotpNow(otpUser->BaseTotp, otpVal);
  }
  if (res == false) {
    printf("calcExpectedOtpOfWaterMeter failed, can't calulate expected OTP code, error: %s\n", errStr);
    Utils_Free(otpVal);
    return false;
  }
  return true;
}

static void clean(EntityManager *entityManager) {
  WaterMeter_Clean();
  EntityManager_FreeAll(entityManager);
  EntityManager_RemoveRegisteredPropertyList();
}

static bool storeToFile(EntityManager *entityManager, const char *fileName, const unsigned char *secret, const unsigned char *salt) {
  if (EntityManager_Store(entityManager, fileName, secret, salt) == false) {
    printf("Error while storing data to file '%s', error %s\n", fileName, errStr);
    return false;
  }
  return true;
}

int main(void) {
  int32_t i=0, value = 0, len=0;
  char *otpVal = NULL, *totpVal = NULL;
  const char *fileName = "water-meter.txt";
  const unsigned char *otpSecret = ((const unsigned char *)"a12T3b39");
  const char *technicianName = "John", *otherUserName = "otherUser";
  const char *usersList[] = {technicianName, otherUserName};
  const char *resourceName = "WaterMeter";
  const char *permission = "Can read";
  unsigned char *storageSecret = NULL;
  const unsigned char *storageSalt = ((const unsigned char *)"The salt");
  EntityManager entityManager;

  if (Utils_GenerateNewValidPassword(&storageSecret, SECRET_LEN) == false) {
    printf("Fatal error: can't generate a new valid password, error: %s\n", errStr);
    return false;
  }
  len = sizeof(usersList) / sizeof(char *);
  printf("This example shows how to use One Time Password (OTP).\n");
  printf("In this example a smart water meter returns its current value only to users with the correct one time password.\n");
  printf("This example starts with the generation of two users (a technician and a customer) and a resource (a water meter).\n");
  printf("Next, an ACL is added to the water meter in which only the technician is allowed to read the value of the water meter value.\n");
  printf("Each time the technician has to read the water meter, it calculates the next OTP and uses it \n");
  printf("when attempting to read the water meter value. If the technician's OTP matches the one calculated internally\n");
  printf("it returns the current value. This example shows how to use HOTP (counter based OTP) as well as TOTP (time base OTP).\n");
  printf("Note: In order to use the time based OTP there should be a delay of OTP time base window (default is 30 sec)\n");
  printf("between consecutive call attempts. This is done in order to protect against replay attacks.\n");
  printf("\n\n");
  EntityManager_New(&entityManager);
  do {
    if (WaterMeter_InitWaterMeter(otpSecret) == false ||
        addUsersAndResource(&entityManager, usersList, len, resourceName) == false ||
        addPermission(&entityManager, resourceName, technicianName, permission) == false ||
        createAndAddOtpToResource(&entityManager, resourceName, otpSecret) == false ||
        calcExpectedOtpOfWaterMeter(&entityManager, technicianName, resourceName, permission, TOTP_TYPE, &totpVal) == false)
      break;
    for (i=0 ; i<2 ; i++) {
      if (calcExpectedOtpOfWaterMeter(&entityManager, technicianName, resourceName, permission, HOTP_TYPE, &otpVal) == false)
        continue;
      if (WaterMeter_ReadWaterMeterValue(otpVal, HOTP_TYPE, &value) == true) {
        printf("Using HOTP: The curent '%s' value is: %d\n", resourceName, value);
        syncOtpCounters(&entityManager, resourceName, otpVal);
      }else {
        printf("Can't get '%s' value (using HOTP), error %s\n", resourceName, errStr);
        break;
      }
      Utils_Free(otpVal);
    }
    // Unauthorized user is tring to read the water meter
    if (calcExpectedOtpOfWaterMeter(&entityManager, otherUserName, resourceName, permission, TOTP_TYPE, &otpVal) == true) {
      printf("Error: User '%s' read the water meter despite not bing allowed to\n", otherUserName);
    }else {
      printf("User '%s' is not allowed to read the water meter\n", otherUserName);
    }
    // Read the water meter using time based OTP
    // Note: In order to use the time based OTP there should be a delay of OTP time base window (default is 30 sec)
    if (WaterMeter_ReadWaterMeterValue(totpVal, TOTP_TYPE, &value) == true) {
      printf("Using TOTP: The curent '%s' value is: %d\n", resourceName, value);
    }else {
      printf("Can't get '%s' value (using TOTP), error %s\n", resourceName, errStr);
      break;
    }
    storeToFile(&entityManager, fileName, storageSecret, storageSalt);
  }while (false);
  Utils_Free(storageSecret);
  Utils_Free(totpVal);
  clean(&entityManager);
  return true;
}
