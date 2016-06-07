#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/entity/entityManager_int.h"
#include "libsecurity/salt/salt.h"
#include "libsecurity/password/password.h"
#include "libsecurity/otp/otpUser.h"
#include "libsecurity/accounts/accounts.h"
#include "libsecurity/acl/acl.h"

#define NUM_OF_USERS 4
#define MAX_USER_NAME 20

#define SECRET ((unsigned char *)"12345678123456781234567812345678")
#define SALT ((unsigned char *)"abcd")

const char *groupName = "group1";
const char *userNameFmt = "User %d";
const char *groupNameFmt = "Group: %d";
const char *resourceNameFmt = "Resouce : %d";

STATIC bool addMembers(EntityManager *entityManager, const char *groupName, int16_t len, int16_t expected) {
  int16_t i = 0;
  bool ret = false;
  char userName[MAX_USER_NAME];

  for (i = 0; i < len; i++) {
    snprintf(userName, sizeof(userName), userNameFmt, i);
    EntityManager_AddUser(entityManager, userName);
    ret = EntityManager_AddUserToGroup(entityManager, groupName, userName);
    if (expected == true && ret == false) {
      snprintf(errStr, sizeof(errStr), "can't add the valid user '%s' to group '%s'", userName, groupName);
      return false;
    } else if (expected == false && ret == true) {
      snprintf(errStr, sizeof(errStr), "attempting to add an existing user '%s' to group '%s'", userName, groupName);
      return false;
    }
    if (EntityManager_IsUserPartOfAGroup(entityManager, groupName, userName) == false) {
      snprintf(errStr, sizeof(errStr), "user '%s' was added to group but was not "
                                       "found in group '%s' members",
               userName, groupName);
      return false;
    }
  }
  return true;
}

STATIC bool removeMembers(EntityManager *entityManager, const char *groupName, int16_t len, int16_t expected) {
  int16_t i = 0;
  bool ret = false;
  char userName[MAX_USER_NAME];

  for (i = 0; i < len; i++) {
    snprintf(userName, sizeof(userName), userNameFmt, i);
    ret = EntityManager_RemoveUserFromGroup(entityManager, groupName, userName);
    if (expected == true && ret == false) {
      snprintf(errStr, sizeof(errStr), "Error: Can't remove the valid user '%s' from group '%s'", userName, groupName);
      return false;
    } else if (expected == false && ret == true) {
      snprintf(errStr, sizeof(errStr), "Error: Removed an already removed member '%s' from group '%s'", userName, groupName);
      return false;
    }
    if (EntityManager_IsUserPartOfAGroup(entityManager, groupName, userName) == true) {
      snprintf(errStr, sizeof(errStr), "Error: User '%s' was found in group '%s' after it was removed", userName, groupName);
      return false;
    }
  }
  return true;
}

// Test that an nil entityManager, user/group/resource can't be added to the
// entity list
// Verify that when a member was added, it is in the members list
// Verify that the same member can be added only once
// Verify thea member is removed only once
// Verift that at the end of the test, the member list must by empty
STATIC bool testAddRemoveMember() {
  int16_t i = 0, len = 0;
  bool expected[2] = { true, false }, pass = true;
  groupData *gEntity = NULL;
  EntityManager e1, *entityManager;

  EntityManager_New(&e1);
  entityManager = &e1;
  len = sizeof(expected) / sizeof(bool);
  if (EntityManager_AddUser(NULL, "a") == true || EntityManager_AddUser(entityManager, NULL) == true ||
      EntityManager_AddGroup(entityManager, NULL) == true || EntityManager_AddResource(entityManager, NULL) == true) {
    printf("testAddRemoveMember failed, add NULL entity to entityManager\n");
    pass = false;
  }
  EntityManager_AddGroup(entityManager, groupName);
  for (i = 0; i < len; i++) {
    if (addMembers(entityManager, groupName, NUM_OF_USERS, expected[i]) == false) {
      printf("testAddRemoveMember failed in add, %s\n", errStr);
      pass = false;
    }
  }
  for (i = 0; i < len; i++) {
    if (removeMembers(entityManager, groupName, NUM_OF_USERS, expected[i]) == false) {
      printf("testAddRemoveMember failed in remove, error: %s\n", errStr);
      pass = false;
    }
  }
  if (getGroup(entityManager, groupName, (void **)(&gEntity)) == false) {
    pass = false;
  }
  if (hcount(gEntity->Members) != 0) {
    printf("testAddRemoveMember failed, the members list must be empty, len %d\n", (int16_t)(hcount(gEntity->Members)));
    printGroup(stdout, "", gEntity);
    pass = false;
  }
  EntityManager_FreeAll(entityManager);
  return pass;
}

// Verift that 2 entities are equal only if all their data is equal
STATIC bool testEntityListAreEqual() {
  int16_t i = 0, j = 0, len = 3;
  bool ret = false, pass = true;
  char groupName[3][MAX_USER_NAME], userName[MAX_USER_NAME];
  groupData *g1 = NULL, *g2 = NULL;
  EntityManager e1, e2, *entityManager1, *entityManager2;
  AmUserInfoS *amUser = NULL;

  EntityManager_New(&e1);
  EntityManager_New(&e2);
  entityManager1 = &e1;
  entityManager2 = &e2;
  for (i = 0; i < len; i++) {
    snprintf(groupName[i], sizeof(groupName[i]), groupNameFmt, i + 1);
    EntityManager_AddGroup(entityManager1, groupName[i]);
    EntityManager_AddGroup(entityManager2, groupName[i]);
    addMembers(entityManager1, groupName[i], NUM_OF_USERS, true);
    addMembers(entityManager2, groupName[i], NUM_OF_USERS, true);
    if (EntityManager_IsEqual(entityManager1, entityManager2) == false) {
      printf("Test fail: the same entity managers are not equal\n");
      EntityManager_Print(stdout, "EntityManager1:\n", entityManager1);
      EntityManager_Print(stdout, "EntityManager2:\n", entityManager2);
      pass = false;
    }
  }
  snprintf(userName, sizeof(userName), userNameFmt, 0);
  EntityManager_RemoveUserFromGroup(entityManager1, groupName[0], userName);
  Accounts_NewUser(&amUser, USER_PERMISSION_STR, SECRET, SALT);
  EntityManager_RegisterProperty(entityManager2, groupName[1], AM_PROPERTY_NAME, (void *)amUser);
  for (i = 0; i < len; i++) {
    getGroup(entityManager1, groupName[i], (void **)(&g1));
    for (j = 0; j < len; j++) {
      getGroup(entityManager2, groupName[j], (void **)(&g2));
      ret = isEqualGroups((void *)g1, (void *)g2);
      if (i != j && ret == true) {
        printf("Test fail: 2 different groups received equal true:\n");
        printGroup(stdout, "Group1:\n", g1);
        printGroup(stdout, "Group2:\n", g2);
        pass = false;
      }
    }
  }
  if (EntityManager_IsEqual(entityManager1, entityManager2) == true) {
    printf("Test fail: different entity managers are equal\n");
    EntityManager_PrintFull(stdout, "EntityManager1:\n", entityManager1);
    EntityManager_PrintFull(stdout, "EntityManager2:\n", entityManager2);
    pass = false;
  }
  EntityManager_FreeAll(entityManager1);
  EntityManager_FreeAll(entityManager2);
  return pass;
}

STATIC bool addRemoveProperty(EntityManager *entityManager, char *name) {
  int16_t i = 0, len = 0, count = 0, expectedCount = 0;
  bool pass = true, expected[2] = { true, false }, ret = false;
  userData *user = NULL;
  groupData *group = NULL;
  resourceData *resource = NULL;
  AmUserInfoS *amUser = NULL;
  void *tmp;

  len = sizeof(expected) / sizeof(bool);
  Accounts_NewUser(&amUser, USER_PERMISSION_STR, SECRET, SALT);
  EntityManager_RegisterProperty(entityManager, name, AM_PROPERTY_NAME, (void *)amUser);
  ret = EntityManager_GetProperty(entityManager, name, AM_PROPERTY_NAME, &tmp);
  if (ret == false) {
    printf("Error: Property '%s' added to property list but was not found in "
           "property list of "
           "entity, %s\n",
           AM_PROPERTY_NAME, errStr);
    pass = false;
  }
  for (i = 0; i < len; i++) {
    ret = EntityManager_RemoveProperty(entityManager, name, AM_PROPERTY_NAME, true);
    if (ret != expected[i]) {
      printf("Test fail: ret %d, expected %d error %s\n", ret, expected[i], errStr);
      pass = false;
    }
  }
  if (EntityManager_IsEntityInUsersList(entityManager, name) == true) {
    getUser(entityManager, name, (void **)(&user));
    count = hcount(user->PropertiesData->Items);
    expectedCount = 0;
  } else if (EntityManager_IsEntityInGroupsList(entityManager, name)) {
    getGroup(entityManager, name, (void **)(&group));
    count = hcount(group->PropertiesData->Items);
    expectedCount = 0;
  } else {
    getResource(entityManager, name, (void **)(&resource));
    count = hcount(resource->PropertiesData->Items);
    expectedCount = 1; // the ACL is connected to the resource
  }
  if (count != expectedCount) {
    printf("Test fail: The property list of '%s' must be %d, length = %d\n", name, expectedCount, count);
    EntityManager_PrintFull(stdout, "Entity:", entityManager);
    pass = false;
  }
  return pass;
}

// Verify that when a property was added, it is in the property list
// Verify that the new property override old one
// Verify that property can be removed multiple times
// Verift that at the end of the test, the property list must by empty
STATIC bool testAddRemoveProperty() {
  bool ret = true;
  char *name = "name1";
  EntityManager e1, *entityManager;
  EntityManager_New(&e1);
  entityManager = &e1;

  EntityManager_AddUser(entityManager, name);
  ret = ret && addRemoveProperty(entityManager, name);
  EntityManager_RemoveUser(entityManager, name);
  EntityManager_AddGroup(entityManager, name);
  ret = ret && addRemoveProperty(entityManager, name);
  EntityManager_RemoveGroup(entityManager, name);
  EntityManager_AddResource(entityManager, name);
  ret = ret && addRemoveProperty(entityManager, name);
  EntityManager_FreeAll(entityManager);
  return ret;
}

// Each entry will hold idx-1 permissions and will be in all predicessors
// entities as member
STATIC bool generateAndAddAcl(EntityManager *entityManager, int16_t numOfUsers, int16_t numOfGroups) {
  int16_t i = 0, j = 0;
  char name[MAX_USER_NAME], permission[MAX_USER_NAME], resourceName[MAX_USER_NAME];

  snprintf(resourceName, sizeof(resourceName), resourceNameFmt, 0);
  for (i = 0; i < numOfUsers; i++) {
    snprintf(name, sizeof(name), userNameFmt, i);
    for (j = 0; j <= i; j++) {
      snprintf(permission, MAX_USER_NAME, "read-%d", j + 1);
      Acl_AddPermissionToResource(entityManager, resourceName, name, permission);
    }
  }
  for (i = 0; i < numOfGroups; i++) {
    snprintf(name, sizeof(name), groupNameFmt, i);
    for (j = 0; j < i; j++) {
      snprintf(permission, sizeof(permission), "write %d", j + 1);
      Acl_AddPermissionToResource(entityManager, resourceName, name, permission);
    }
  }
  Acl_AddPermissionToResource(entityManager, resourceName, ALL_ACL_NAME, "all can read");
  return true;
}

STATIC bool generateAndAddEntities(EntityManager *entityManager, int16_t numOfUsers, int16_t numOfGroups, int16_t numOfResources) {
  int16_t i = 0, min = numOfUsers;
  char userName[MAX_USER_NAME], groupName[MAX_USER_NAME], resourceName[MAX_USER_NAME];

  for (i = 0; i < numOfUsers; i++) {
    snprintf(userName, sizeof(userName), userNameFmt, i);
    EntityManager_AddUser(entityManager, userName);
  }
  for (i = 0; i < numOfGroups; i++) {
    snprintf(groupName, sizeof(groupName), groupNameFmt, i);
    EntityManager_AddGroup(entityManager, groupName);
    if (i < numOfUsers) min = i;
    if (addMembers(entityManager, groupName, min, true) == false) {
      printf("Error while generating groups: '%s'\n", errStr);
      return false;
    }
  }
  for (i = 0; i < numOfResources; i++) {
    snprintf(resourceName, sizeof(resourceName), resourceNameFmt, i);
    EntityManager_AddResource(entityManager, resourceName);
  }
  return true;
}

STATIC bool generateAndAddProperties(EntityManager *entityManager, int16_t numOfUsers, int16_t numOfGroups, int16_t numOfResources) {
  int16_t i = 0;
  char name[MAX_USER_NAME];
  AmUserInfoS *amUser = NULL;
  OtpUserS *otpUser = NULL;
  PwdS *pwdUser = NULL;

  for (i = 0; i < numOfUsers; i++) {
    if (Accounts_NewUser(&amUser, SUPER_USER_PERMISSION_STR, SECRET, SALT) == false) {
      printf("Error while generating Accouns user: %s\n", errStr);
      return false;
    }
    snprintf(name, sizeof(name), userNameFmt, i);
    EntityManager_RegisterProperty(entityManager, name, AM_PROPERTY_NAME, (void *)amUser);
    if (Pwd_NewUserPwd(&pwdUser, SECRET, SALT) == false) {
      printf("Error while generating Password for user: %s\n", errStr);
      return false;
    }
    EntityManager_RegisterProperty(entityManager, name, PWD_PROPERTY_NAME, (void *)pwdUser);

    if (i < numOfGroups) {
      if (OtpUser_NewSimpleUser(&otpUser, SECRET) == false) {
        printf("Error while generating Otp user: %s\n", errStr);
        return false;
      }
      snprintf(name, sizeof(name), groupNameFmt, i);
      EntityManager_RegisterProperty(entityManager, name, OTP_PROPERTY_NAME, (void *)otpUser);
    }

    if (i < numOfResources) {
      if (Pwd_NewUserPwd(&pwdUser, SECRET, SALT) == false) {
        printf("Error while generating Password for user: %s\n", errStr);
        return false;
      }
      snprintf(name, sizeof(name), resourceNameFmt, i);
      EntityManager_RegisterProperty(entityManager, name, PWD_PROPERTY_NAME, (void *)pwdUser);
    }
  }
  return generateAndAddAcl(entityManager, numOfUsers, numOfGroups);
}

// Generate numOfUSers users, numOfGroups groups each with numOfUsers users and
// numOfResources
// resources
// Add Accounts, Otp and Password properties to the first user,
// Add password property to the last group and OTP property to the last resource
STATIC bool generateData(EntityManager *entityManager, int16_t numOfUsers, int16_t numOfGroups, int16_t numOfResources) {
  if (generateAndAddEntities(entityManager, numOfUsers, numOfGroups, numOfResources) == false) return false;
  return generateAndAddProperties(entityManager, numOfUsers, numOfGroups, numOfResources);
}

STATIC bool testStoreLoad() {
  int16_t i = 0, numOfUsers = 6, numOfGroups = 2, numOfResources = 3, len = 2;
  bool pass = true;
  char *fileName = "try.txt";
  EntityManager e[2], *entityManager[2];

  for (i = 0; i < len; i++) {
    EntityManager_New(&(e[i]));
    entityManager[i] = &(e[i]);
  }
  if (generateData(entityManager[0], numOfUsers, numOfGroups, numOfResources) == false) return false;

  pass = EntityManager_Store(entityManager[0], fileName, SECRET, SALT);
  if (pass == false) {
    printf("Error while storing data to file '%s', error %s\n", fileName, errStr);
  }
  if (pass == true) {
    pass = EntityManager_Load(&(entityManager[1]), fileName, SECRET, SALT);
    if (pass == false) {
      printf("Error while loading data to file '%s', error %s\n", fileName, errStr);
    }
    if (pass == true) pass = EntityManager_IsEqual(entityManager[0], entityManager[1]);
    if (pass == false) {
      printf("Test fail, Stored entity data != loaded one\n");
      EntityManager_PrintFull(stdout, "Stored entityManager:", entityManager[0]);
      EntityManager_PrintFull(stdout, "Loaded entityManager:", entityManager[1]);
    }
  }
#ifndef MBED_OS
  FILE *devNull = fopen("/dev/null", "w");
  EntityManager_Print(devNull, "Test Entity", entityManager[0]);
  EntityManager_PrintFull(devNull, "Test Entity full", entityManager[1]);
  fclose(devNull);
#endif
  for (i = 0; i < len; i++) {
    EntityManager_FreeAll(entityManager[i]);
  }
  remove(fileName);
  return pass;
}

// Create a data, verify that the user is in the relevant groups and have the
// relevant permissions
// remove the user, add it again and verify it doesn't have the permissions and
// is not in the groups
STATIC bool testRemoveUserFromGroupAndAcl() {
  int16_t i = 0, len = 0, ret, numOfUsers = 2, numOfGroups = 2, numOfResources = 1;
  bool pass = true;
  char userName[MAX_USER_NAME], groupName[MAX_USER_NAME], resourceName[MAX_USER_NAME];
  EntityManager e, *entityManager;
  AclPermissionsS *perVec = NULL;

  EntityManager_New(&e);
  entityManager = &e;
  snprintf(userName, sizeof(userName), userNameFmt, 0);
  snprintf(groupName, sizeof(groupName), groupNameFmt, numOfGroups - 1);
  snprintf(resourceName, sizeof(resourceName), resourceNameFmt, 0);
  if (generateData(entityManager, numOfUsers, numOfGroups, numOfResources) == false) return false;
  for (i = 0; i < 3; i++) {
    ret = EntityManager_IsUserPartOfAGroup(entityManager, groupName, userName);
    Acl_NewPermissionsList("TestPermissions", &perVec);
    Acl_GetUserPermissions(entityManager, resourceName, userName, &perVec);
    len = hcount(perVec->Permissions);
    if (i == 0 && (ret == false || len == 0)) {
      printf("testRemoveUserFromGroupAndAcl fail, user '%s' must be in group "
             "'%s' and have "
             "permissions for resource '%s'\n",
             userName, groupName, resourceName);
      EntityManager_PrintFull(stdout, "Entity Manager before remove the user\n", entityManager);
      pass = false;
      break;
    }
    if (i == 1 && (ret == true || len != 0)) {
      printf("testRemoveUserFromGroupAndAcl fail, is user '%s' in group '%s' "
             "%d, number of "
             "permissions for resource '%s' %d\n",
             userName, groupName, ret, resourceName, len);
      EntityManager_PrintFull(stdout, "Entity Manager after remove the user\n", entityManager);
      pass = false;
    }
    if (i == 2 && (ret == true || len != 1)) { // len is 1 for the all permissions
      printf("testRemoveUserFromGroupAndAcl fail, is user '%s' in group '%s' "
             "%d, number of "
             "permissions for resource '%s' %d\n",
             userName, groupName, ret, resourceName, len);
      EntityManager_PrintFull(stdout, "Entity Manager after remove and add again user\n", entityManager);
      pass = false;
    }
    EntityManager_RemoveUser(entityManager, userName);
    if (i == 1) EntityManager_AddUser(entityManager, userName);
    Acl_FreePermissionsList(perVec);
  }
  EntityManager_FreeAll(entityManager);
  return pass;
}

STATIC bool testEntityCorners() {
  int16_t i, len = 0;
  bool pass = true;
  char *r1 = "r1", *r2 = "r2";
  EntityManager e, *entityManager;
  resourceData *resource1 = NULL, *resource2 = NULL;

  typedef bool (*testFunc)(const EntityManager *entityManager, const char *name);
  typedef bool (*testFunc1)(EntityManager *entityManager, const char *name);

  testFunc func[] = { EntityManager_IsEntityInUsersList, EntityManager_IsEntityInGroupsList, EntityManager_IsEntityInResourcesList,
                      EntityManager_IsEntityInList };
  testFunc1 func1[] = { EntityManager_RemoveUser, EntityManager_RemoveGroup, EntityManager_RemoveResource, EntityManager_Free };

  len = sizeof(func) / sizeof(testFunc);
  for (i = 0; i < len; i++) {
    if (func[i](NULL, "A") == true) {
      printf("testEntityCorners fail, func idx %d with NULL entityManager returned true\n", i);
      pass = false;
    }
  }
  len = sizeof(func1) / sizeof(testFunc1);
  for (i = 0; i < len; i++) {
    if (func1[i](NULL, "A") == true) {
      printf("testEntityCorners fail, func1 idx %d with NULL entityManager returned true\n", i);
      pass = false;
    }
  }
  EntityManager_FreeAll(NULL);
  if (checkDataAndGetGroup(NULL, NULL, NULL, NULL) == true || EntityManager_AddUserToGroup(NULL, NULL, NULL) == true ||
      EntityManager_StoreName(NULL, NULL, NULL, NULL) == true || EntityManager_LoadName(NULL, NULL, NULL, NULL) == true ||
      EntityManager_Store(NULL, NULL, NULL, NULL) == true || EntityManager_Load(NULL, NULL, NULL, NULL) == true ||
      EntityManager_AddUserToGroup(NULL, NULL, NULL) == true || getEntity(NULL, NULL, NULL) == true ||
      EntityManager_RegisterProperty(NULL, NULL, NULL, NULL) == true || EntityManager_RemoveProperty(NULL, NULL, NULL, NULL) == true ||
      EntityManager_GetProperty(NULL, NULL, NULL, NULL) == true ||
      EntityManager_RegisterPropertyHandleFunc(NULL, NULL, NULL, NULL, NULL, NULL) == true || addUserToGroup(NULL, NULL) == true ||
      loadMembers(NULL, NULL, NULL) == true || load(NULL, NULL, NULL, NULL) == true || isEqualProperties(NULL, NULL) == true ||
      registerProperty(NULL, NULL, NULL) == true || removeProperty(NULL, NULL, true) == true || getProperty(NULL, NULL, NULL) == true) {
    printf("testEntityCorners fail, call func with NULL entityManager returned true\n");
    pass = false;
  }
  EntityManager_RemoveRegisteredPropertyList();

  EntityManager_New(&e);
  entityManager = &e;
  if (EntityManager_RegisterProperty(entityManager, "a", "undef", (void *)"undef") == true) {
    printf("testEntityCorners fail, call EntityManager_RegisterProperty with undefined module returned true\n");
    pass = false;
  }
  EntityManager_AddResource(entityManager, r1);
  EntityManager_AddResource(entityManager, r2);
  getResource(entityManager, r1, (void **)&resource1);
  getResource(entityManager, r2, (void **)&resource2);
  if (isEqualResources(resource1, resource2) == true || isEqualResources(resource1, resource2) == true) {
    printf("testEntityCorners fail, call isEqualResources with different resources returned true\n");
    pass = false;
  }
  EntityManager_RemoveResource(entityManager, "r1");
  EntityManager_FreeAll(entityManager);
  return pass;
}

#ifdef MBED_OS
int16_t testEntity()
#else
int main()
#endif
{
  bool pass = true;
  int16_t i, len = 0;
  char *res;

  Entity_TestMode = true;
  Utils_TestFuncS callFunc[] = { 
                                 { "testAddRemoveMember", testAddRemoveMember },
                                 { "testEntityListAreEqual", testEntityListAreEqual },
                                 { "testAddRemoveProperty", testAddRemoveProperty },
                                 { "testRemoveUserFromGroupAndAcl", testRemoveUserFromGroupAndAcl },
                                 { "testStoreLoad", testStoreLoad },
                                 { "testEntityCorners", testEntityCorners } 
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
