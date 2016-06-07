#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/entity/entityManager.h"
#include "libsecurity/acl/acl.h"
#include "libsecurity/salt/salt.h"
#include "libsecurity/password/password.h"

static const char *groupName = "Family";
static const char *bossName = "The boss";
static const char *kid1Name = "Older kid";
static const char *kid2Name = "Younger kid";
static const char *visitorName = "Visitor";
static const char *resourceName = "TV";
static const char *bossPermission = "Can use PPTV";
static const char *oldersPermission = "Can change station to chanel 55 (sport)";
static const char *groupPermission = "Can change station to channel 22";
static const char *allPermission = "Can Power on/turn off";

// Creating new users and group entities and adding users to the group
static bool createAndAddMembers(EntityManager *entityManager, const char *groupName, const char *usersList[], int numOfUsers, const char *groupMembers[], int groupLen) {
  int16_t i=0;

  EntityManager_AddGroup(entityManager, groupName);
  for (i=0 ; i<numOfUsers ; i++) {
    EntityManager_AddUser(entityManager, usersList[i]);
  }
  for (i=0 ; i<groupLen ; i++) {
    EntityManager_AddUserToGroup(entityManager, groupName, groupMembers[i]);
  }
  return true;
}

// Setting the resource's permissions for each entity (user/group or open to all)
// Permissions:  
//  1. Can use PPTVT is allowed only to the boss
//  2. Can change to sport channel 55 is allowed to the olders (boss and the oldest kid)
//  3. Can watch channel 22 is allowed to all the family members
//  4. To poweron and power off the TV is allowed to everybody
static bool addAcl(EntityManager *entityManager, const char *resourceName, const char *groupName) {
  if (EntityManager_AddResource(entityManager, resourceName) == false) {
    printf("Error: Can't add resource '%s' to the entity manager, error: %s\n", resourceName, errStr);
    return false;
  }
  Acl_AddPermissionToResource(entityManager, resourceName, bossName, bossPermission);
  Acl_AddPermissionToResource(entityManager, resourceName, bossName, oldersPermission);
  Acl_AddPermissionToResource(entityManager, resourceName, kid1Name, oldersPermission);
  Acl_AddPermissionToResource(entityManager, resourceName, groupName, groupPermission);
  Acl_AddPermissionToResource(entityManager, resourceName, ALL_ACL_NAME, allPermission);
  return true;
}

// Checking which permissions (in the context of the resource) each of the users has
static bool checkPermissions(EntityManager *entityManager, const char *resourceName, const char *usersList[], int numOfUsers, const char *permissions[], int numOfPermissions) {
  int16_t i=0, j=0;
  bool res=false;
  const char *name=NULL;
  const char *haveStr[] = {"doesn't have", "has"};
  AclPermissionsS *permissionsVec=NULL;
  htab *whoCanUse=NULL;

  for (i=0 ; i<numOfUsers ; i++) {
    for (j=0 ; j<numOfPermissions ; j++) {
      res = Acl_CheckEntityPermission(entityManager, resourceName, usersList[i], permissions[j]);
      printf("User '%s' %s permission '%s' for resource '%s'\n", usersList[i], haveStr[res], permissions[j], resourceName);
    }
  }

  whoCanUse = hcreate(H_TAB_SIZE);
  Acl_WhoUseAPermission(entityManager, allPermission, whoCanUse);
  printf("Users that have permission '%s':\n", allPermission);
  Utils_PrintHashKeys("", "  -", whoCanUse);
  hdestroy(whoCanUse);

  whoCanUse = hcreate(H_TAB_SIZE);
  Acl_WhoUseAPermission(entityManager, groupPermission, whoCanUse);
  printf("Users that have group permission '%s'\n", groupPermission);
  Utils_PrintHashKeys("", "  -", whoCanUse);
  hdestroy(whoCanUse);

  name = bossName;
  Acl_NewPermissionsList("", &permissionsVec);
  Acl_GetUserPermissions(entityManager, resourceName, name, &permissionsVec);
  printf("User '%s' has for resource '%s' ", name, resourceName);
  Acl_PrintPermissionsList(stdout, "", permissionsVec);
  Acl_FreePermissionsList(permissionsVec);
  return true;
}

static void clean(EntityManager *entityManager) {
  EntityManager_FreeAll(entityManager);
  EntityManager_RemoveRegisteredPropertyList();
}

//  Storing the data in a secure file for further useage
static bool storeToFile(EntityManager *entityManager, const char *fileName, const unsigned char *secret, const unsigned char *salt) {
  if (EntityManager_Store(entityManager, fileName, secret, salt) == false) {
    printf("Error while storing data to file '%s', error %s\n", fileName, errStr);
    return false;
  }
  return true;
}

int main(void) {
  int16_t numOfUsers = 0, groupLen=0, numOfPermissions=0;
  const char *fileName = "TV-acl.txt";
  const char *groupMembers[] = {bossName, kid1Name, kid2Name};
  const char *usersList[] = {bossName, kid1Name, kid2Name, visitorName};
  const char *permissions[] = {bossPermission, oldersPermission, groupPermission, allPermission};
  unsigned char *storageSecret = NULL;
  const unsigned char *storageSalt = ((const unsigned char *)"The salt");

  EntityManager entityManager;
  if (Utils_GenerateNewValidPassword(&storageSecret, SECRET_LEN) == false) {
    printf("Fatal error: can't generate a new valid password, error: %s\n", errStr);
    return false;
  }
  EntityManager_New(&entityManager);
  numOfUsers = sizeof(usersList) / sizeof(char *);
  groupLen = sizeof(groupMembers) / sizeof(char *);
  numOfPermissions = sizeof(permissions) / sizeof(char *);

  printf("This example shows how to set ACL permissions of a resource, in this case a smart TV, for users and groups of users.\n");
  printf("The first step is adding the groups (in this case, a single group) and users to the entity list.\n");
  printf("the second step is adding users to the groups they belong to.\n");
  printf("The third step is setting the users' and groups' permissions, when permissions can be set for:\n");
  printf("1. a specific user\n");
  printf("2. a group of users\n");
  printf("3. all users\n");
  printf("This example, includes all 3 types of permissions and demonstrates the way affect each user\n");
  printf("Notes:\n- Permissions are strings, and are not limited to a specific set of values\n");
  printf("- The data is saved in a secure way to a file and is later used whenever a user attepts to access the resource");
  printf("\n\n");
  createAndAddMembers(&entityManager, groupName, usersList, numOfUsers, groupMembers, groupLen);
  addAcl(&entityManager, resourceName, groupName);
  checkPermissions(&entityManager, resourceName, usersList, numOfUsers, permissions, numOfPermissions);
  storeToFile(&entityManager, fileName, storageSecret, storageSalt);

  Utils_Free(storageSecret);
  clean(&entityManager);
  return true;
}
