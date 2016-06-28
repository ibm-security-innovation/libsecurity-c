#include "example.h"

static const unsigned char *PwdSecret = ((const unsigned char *)"A2B12ta@$");
static const unsigned char *PwdSalt = ((const unsigned char *)"Salt1");

static bool checkPwd(EntityManager *entityManager, const char *userName) {
  int16_t pwdLen = 10;
  unsigned char *newPwd=NULL, *tPwd = NULL;
  const unsigned char *wrongPassword = (const unsigned char *) "wrong password";
  PwdS *pwdUser=NULL;

  if (EntityManager_GetProperty(entityManager, userName, PWD_PROPERTY_NAME, (void **)&pwdUser) == false) {
    printf("checkPwd failed, can't get the 'Password' property for user '%s', Error: %s\n", userName, errStr);
    return false;
  }
  if (Pwd_VerifyPassword(pwdUser, PwdSecret)) {
      printf("checkPwd, password '%s' matches as expected\n", PwdSecret);
  }else  {
    printf("checkPwd failed, Current password '%s' did not match, error: %s\n", PwdSecret, errStr);
    return false;
  }
  Utils_GenerateNewValidPassword(&newPwd, pwdLen);
  if (Pwd_UpdatePassword(pwdUser, PwdSecret, newPwd, STRENGTH_GOOD)) {
      printf("checkPwd, password '%s' was successfully updated to the new password '%s'\n", PwdSecret, newPwd);
  }else {
    printf("checkPwd failed, Can't update password '%s' to the requested new password '%s', error: %s\n", PwdSecret, newPwd, errStr);
    Utils_Free(newPwd);
    return false;
  }
  if (Pwd_VerifyPassword(pwdUser, PwdSecret)) {
    printf("checkPwd failed, Matches the old password '%s' after password was changed\n", PwdSecret);
    Utils_Free(newPwd);
    return false;
  }else {
     printf("checkPwd, password '%s' was not matched (it is the old password), as expected\n", PwdSecret);
  }
  if (Pwd_VerifyPassword(pwdUser, newPwd)) {
      printf("checkPwd, password '%s' matched as expected\n", newPwd);
  }else {
    printf("checkPwd failed, Current password '%s' did not match, error: %s\n", newPwd, errStr);
    Utils_Free(newPwd);
    return false;
  }
  if (Pwd_UpdatePassword(pwdUser, newPwd, PwdSecret, STRENGTH_GOOD) == false) {
      printf("checkPwd, new password '%s' was not updated, the error is %s\n", PwdSecret, errStr);
  }else {
    printf("checkPwd failed, Password '%s' updated successfully to the new password '%s', but this password was already used as one of the last %d passwords\n", 
      newPwd, PwdSecret, DEFAULT_NUMBER_OF_OLD_PASSWORDS);
    Utils_Free(newPwd);
    return false;
  }
  Utils_GenerateNewValidPassword(&tPwd, pwdLen);
  Pwd_UpdatePassword(pwdUser, newPwd, tPwd, STRENGTH_GOOD);
  Utils_Free(newPwd);
  Pwd_SetTemporaryPwd(pwdUser, true);
  printf("checkPwd, Update to new password '%s' and set it as a temporay password (turns obsolete after a single use)\n", tPwd);
  if (Pwd_VerifyPassword(pwdUser, tPwd)) {
      printf("checkPwd, first attempt to match the temporray password '%s' was successfull (as expected)\n", tPwd);
  }else {
    printf("checkPwd failed, Current password '%s' did not match, error: %s\n", tPwd, errStr);
    Utils_Free(tPwd);
    return false;
  }
  if (Pwd_VerifyPassword(pwdUser, tPwd) == false) {
      printf("checkPwd, second attempt to match the temporray password '%s' was rejected (as expected), error %s\n", tPwd, errStr);
  }else {
    printf("checkPwd failed, Current password '%s' matched but it was set to be a temporary password (turns obsolete after a single use)\n", tPwd);
    Utils_Free(tPwd);
    return false;
  }
  Utils_GenerateNewValidPassword(&newPwd, pwdLen);
  Pwd_UpdatePassword(pwdUser, tPwd, newPwd, STRENGTH_GOOD);
  Pwd_VerifyPassword(pwdUser, wrongPassword);
  printf("checkPwd, Updated to a new password '%s' and incremented the error counter by 1\n", newPwd);
  Pwd_Print(stdout, "Current password information:\n", pwdUser);
  Utils_Free(tPwd);
  Utils_Free(newPwd);
  return true;
}

static bool createAndAddPwd(EntityManager *entityManager, const char *userName) {
  PwdS *pwdUser;

  if (Pwd_NewUserPwd(&pwdUser, PwdSecret, PwdSalt, STRENGTH_GOOD) == false) {
    printf("createAndAddPwd failed, Can't create OTP user, error: %s\n", errStr);
    return false;
  }
  return EntityManager_RegisterProperty(entityManager, userName, PWD_PROPERTY_NAME, (void *)pwdUser);
}

bool AddPwd(EntityManager *entityManager, int16_t userId) {
  bool pass = true;
  char userName[EXP_MAX_USER_NAME];

  snprintf(userName, sizeof(userName), USER_NAME_FMT, userId);
  pass = createAndAddPwd(entityManager, userName);
  if (pass) {
    pass = checkPwd(entityManager, userName);
  }
  return pass;
}
