#include "example.h"

static void clean(EntityManager *entityManager) {
  EntityManager_FreeAll(entityManager);
  EntityManager_RemoveRegisteredPropertyList();
}

int main(void) {
  EntityManager entityManager;
  int16_t otpUserId = 1, pwdUserId = 2;

  EntityManager_New(&entityManager);

  printf("************ Show entity manager usage: ************\n");
  AddUsersGroups(&entityManager);
  printf("\n\n************ Show ACL usage: ************\n");
  AddAcl(&entityManager);
  printf("\n\n************ Show OTP usage ************\n");
  AddOtp(&entityManager, otpUserId);
  printf("\n\n************ Show Password usage ************\n");
  AddPwd(&entityManager, pwdUserId);
  printf("\n\n************ Show Secure Storage usage ************\n");
  StoreData(&entityManager);

  clean(&entityManager);
  return true;
}
