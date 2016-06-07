#include "example.h"

static bool createGroupUsersAndAddSomeOftheUsersToTheGroup(EntityManager *entityManager, int16_t numOfUsers, const char *groupName) {
  int16_t i=0;
  char userName[EXP_MAX_USER_NAME];

  EntityManager_AddGroup(entityManager, groupName);
  printf("Add group '%s'\n", groupName);
  for (i = 0; i < numOfUsers; i++) {
    snprintf(userName, sizeof(userName), USER_NAME_FMT, i);
    printf("Add user '%s'\n", userName);
    EntityManager_AddUser(entityManager, userName);
    if (i % 2 == 0) {
      if (EntityManager_AddUserToGroup(entityManager, groupName, userName) == false) {
        printf("Error: Can't add the valid user '%s' to group '%s', error: %s", userName, groupName, errStr);
        return false;        
      }
      printf("Add user '%s' to group '%s'\n", userName, groupName);
      if (EntityManager_IsUserPartOfAGroup(entityManager, groupName, userName) == false) {
        printf("Error: user '%s' was added to group but was not found as part of group '%s' members",
               userName, groupName);
        return false;
      }
    }
  }
  return true;
}

static bool createUsersAndGroup(EntityManager *entityManager) {
  char userName[EXP_MAX_USER_NAME];

  if (createGroupUsersAndAddSomeOftheUsersToTheGroup(entityManager, EXP_NUM_OF_USERS, GROUP_NAME_FMT) == false)
    return false;
  EntityManager_PrintFull(stdout, "Entity manager initial status:\n", entityManager);
  snprintf(userName, sizeof(userName), USER_NAME_FMT, EXP_REMOVED_USER_IDX);
  EntityManager_RemoveUser(entityManager, userName);
  printf("Entity manager after removing of user %s:\n", userName);
  EntityManager_PrintFull(stdout, "", entityManager);
  return true;
}

bool AddUsersGroups(EntityManager *entityManager) {
  return createUsersAndGroup(entityManager);
}
