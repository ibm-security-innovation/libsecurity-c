#include "libsecurity/acl/acl_int.h"

#define ACL_ENTRY_NAME "try-entry"
#define BOTH_ENTRY_NAME "both"
#define ALL_PERMISSION "All can user it"
#define ENTRY_PERMISSION "p1"
#define BOTH_PERMISSION "both"
#define DEFAULT_SALT ((unsigned char *)"salt-a1b2c3d")
#define SECRET ((unsigned char *)"a!@#%^&*(()__+_)(}{|PPO?>O2:~`12")

const char *AclName = "Test-Acl";
const char *AclResourceName = "Camera-1";

// Verify that only permissions with value can be added to entty
STATIC bool testAddPermission() {
  int16_t i, len = MAX_PERMISSION_NAME_LEN + 2;
  bool pass = true, ret;
  AclPermissionsS *aclEntry, *aclEntryRef;
  char name[len * 2 + 1];
  EntityManager e1, *entityManager = NULL;

  EntityManager_New(&e1);
  entityManager = &e1;
  Acl_NewPermissionsList("test", &aclEntry);
  Acl_NewPermissionsList("test", &aclEntryRef);
  strcpy(name, "");
  for (i = 0; i < len; i++) {
    ret = addPermissionToEntry(aclEntry, name);
    if (ret == false && strlen(name) > 0 && strlen(name) <= MAX_PERMISSION_NAME_LEN) {
      printf("testAddPermission fail: permission with legal name '%s' was not "
             "added to ACL entry "
             "'%s', error: %s\n",
             name, ALL_ACL_NAME, errStr);
      pass = false;
    } else if (ret == true && (strlen(name) == 0 || strlen(name) > MAX_PERMISSION_NAME_LEN)) {
      printf("testAddAclEntry fail: permission with illegal name '%s' (length "
             "%d), length must be "
             "%d-%d was added to ACL entry '%s'\n",
             name, (int16_t)strlen(name), 1, MAX_PERMISSION_NAME_LEN, ALL_ACL_NAME);
      pass = false;
    }
    strcat(name, "a");
    if (isEqualEntry(aclEntry, aclEntry) == false) {
      printf("testAddAclEntry fail: equal ACL entries did not found equal\n");
      Acl_PrintPermissionsList(stdout, "", aclEntry);
      pass = false;
    }
    ret = addPermissionToEntry(aclEntryRef, name);
    if (ret == true && isEqualEntry(aclEntry, aclEntryRef) == true) {
      printf("testAddAclEntry fail: unequal ACL entries found equal\n");
      Acl_PrintPermissionsList(stdout, "", aclEntry);
      Acl_PrintPermissionsList(stdout, "", aclEntryRef);
      pass = false;
    }
  }
  Acl_FreePermissionsList(aclEntry);
  Acl_FreePermissionsList(aclEntryRef);
  EntityManager_FreeAll(entityManager);
  return pass;
}

STATIC bool setup(EntityManager *entityManager, int16_t len, char **names) {
  int16_t i = 0;
  AclPermissionsS *aclEntry[len];
  AclS *acl;

  EntityManager_AddResource(entityManager, AclResourceName);
  EntityManager_GetProperty(entityManager, AclResourceName, ACL_PROPERTY_NAME, (void **)(&acl));
  for (i = 0; i < len; i++) {
    EntityManager_AddUser(entityManager, names[i]);
    addEntry(acl, names[i], &(aclEntry[i]));
  }
  EntityManager_RegisterProperty(entityManager, AclResourceName, ACL_PROPERTY_NAME, (void *)acl);
  return true;
}

// Verify that a permission can be added/removed only once
// Verify that true is return only for set permissions
// Verify that if ALL permission was set, the entity will recieve true
// Verify that if the permission was set to an entity the check entity is member
// of, a true will be
// recieved
// Verify that if a permission was not set, a false to check is received
STATIC bool testAddRemoveCheckPermission() {
  int16_t i = 0, j = 0;
  bool ret = false, ret0, ret1, ret2, pass = true;
  char *permission[2] = { "add", "no added" };
  char *names[3] = { ALL_ACL_NAME, ACL_ENTRY_NAME, BOTH_ENTRY_NAME };
  EntityManager e1, *entityManager = NULL;
  bool exp[] = { false, true, false, true, false };
  bool exp1[] = { false, true, true, false, false };
  int16_t testLen = -1, namesLen = -1;
  int16_t addRemove[] = { 'r', 'a', 'a', 'r', 'r' };
  AclS *acl = NULL;

  testLen = sizeof(exp) / sizeof(bool);
  namesLen = sizeof(names) / sizeof(char *);
  EntityManager_New(&e1);
  entityManager = &e1;
  EntityManager_AddGroup(entityManager, BOTH_ENTRY_NAME);
  setup(entityManager, namesLen, names);
  // add ACL_ENTRY_NAME as member of BOTH_ENTRY_NAME
  if (EntityManager_AddUserToGroup(entityManager, BOTH_ENTRY_NAME, ACL_ENTRY_NAME) == false) {
    printf("The user '%s' was not added to group '%s', error %s\n", ACL_ENTRY_NAME, BOTH_ENTRY_NAME, errStr);
  }
  if (EntityManager_GetProperty(entityManager, AclResourceName, ACL_PROPERTY_NAME, (void **)(&acl)) == false) {
    printf("Error: Can't get ACL property from '%s'\n", names[i]);
    return false;
  }
  for (i = 0; i < namesLen; i++) {
    for (j = 0; j < testLen; j++) {
      if (addRemove[j] == 'r') {
        ret = Acl_RemovePermissionFromResource(entityManager, AclResourceName, names[i], permission[0]);
        ret1 = Acl_CheckEntityPermission(entityManager, AclResourceName, names[i], permission[0]);
      } else {
        ret = Acl_AddPermissionToResource(entityManager, AclResourceName, names[i], permission[0]);
        ret1 = Acl_CheckEntityPermission(entityManager, AclResourceName, names[i], permission[0]);
        ret2 = Acl_CheckEntityPermission(entityManager, AclResourceName, ACL_ENTRY_NAME, permission[0]);
      }
      ret0 = Acl_CheckEntityPermission(entityManager, AclResourceName, names[i], permission[1]);
      if (ret != exp[j]) {
        printf("testAddRemoveCheckPermission fail: i=%d, j=%d, action %c, "
               "permission '%s' entry "
               "'%s', exp %d, ret %d\n",
               i, j, addRemove[j], permission[0], names[i], exp[j], ret);
        pass = false;
      }
      if (ret1 != exp1[j]) {
        printf("testAddRemoveCheckPermission fail for ret1: i=%d, j=%d, action "
               "%c, permission '%s' "
               "entry '%s', exp1 %d, ret1 %d\n",
               i, j, addRemove[j], permission[0], names[i], exp1[j], ret1);
        pass = false;
      }
      if (addRemove[j] == 'a' && ret2 == false) {
        printf("testAddRemoveCheckPermission fail for ret2: permission must be "
               "set i=%d, j=%d, "
               "action %c, permission '%s' entry '%s', exp2 %d, ret2 %d\n",
               i, j, addRemove[j], permission[0], ACL_ENTRY_NAME, true, ret2);
        pass = false;
      }
      if (ret0 == true) {
        printf("testAddRemoveCheckPermission fail for ret0: permission was "
               "never set for entry "
               "'%s', permission '%s'\n",
               names[i], permission[1]);
        pass = false;
      }
    }
  }
  EntityManager_FreeAll(entityManager);
  return pass;
}

// Verify that an entity permission returns all its permission (including the
// permissions of entity
// it is a member of and the all permission)
// Verify that true is return only for set permissions
// Verify that all permissions return the full list of permissions
// Verify that who uses a permission return the relevant entity list
STATIC bool testGetCheckWhoUseGetAllPermissions() {
  int16_t i = 0, len = 0;
  bool pass = true;
  char *names[4] = { ALL_ACL_NAME, ACL_ENTRY_NAME, BOTH_ENTRY_NAME, "none" };
  char *permissions[4] = { ALL_PERMISSION, ENTRY_PERMISSION, BOTH_PERMISSION, NULL };
  htab *expectedUsersName[4]; // must be the same order as in permissions
  int16_t exp[] = { 1, 3, 2, 1 }; // ACL_ENTRY is also in the BOTH_ENTRY
  int16_t namesLen = -1;
  AclPermissionsS *permissionsVec = NULL;
  htab *whoUses = NULL;
  EntityManager e1, *entityManager = NULL;

  void *a = NULL;
  AclS *acl = NULL;

  namesLen = sizeof(names) / sizeof(char *);
  EntityManager_New(&e1);
  entityManager = &e1;
  EntityManager_AddGroup(entityManager, BOTH_ENTRY_NAME);
  setup(entityManager, namesLen, names);
  // add ACL_ENTRY_NAME as member of BOTH_ENTRY_NAME
  if (EntityManager_AddUserToGroup(entityManager, BOTH_ENTRY_NAME, ACL_ENTRY_NAME) == false) {
    printf("The user '%s' was not added to group '%s', error %s\n", ACL_ENTRY_NAME, BOTH_ENTRY_NAME, errStr);
  }
  if (EntityManager_GetProperty(entityManager, AclResourceName, ACL_PROPERTY_NAME, &a) == false) {
    printf("Error: Can't get ACL property from '%s'\n", names[i]);
    return false;
  }
  acl = (AclS *)a;
  for (i = 0; i < namesLen; i++)
    expectedUsersName[i] = hcreate(H_TAB_SIZE);
  for (i = 0; i < namesLen; i++) {
    if (permissions[i] != NULL) Acl_AddPermissionToResource(entityManager, AclResourceName, names[i], permissions[i]);
    Utils_AddToHash(expectedUsersName[0], (unsigned char *)names[i], strlen(names[i]), "");
    if (strcmp(names[i], ACL_ENTRY_NAME) == 0) Utils_AddToHash(expectedUsersName[1], (unsigned char *)names[i], strlen(names[i]), "");
    if (strcmp(names[i], ACL_ENTRY_NAME) == 0 || strcmp(names[i], BOTH_ENTRY_NAME) == 0)
      Utils_AddToHash(expectedUsersName[2], (unsigned char *)names[i], strlen(names[i]), "");
  }
  // add the ROOT_USER_NAME to all
  Utils_AddToHash(expectedUsersName[0], (unsigned char *)ROOT_USER_NAME, strlen(ROOT_USER_NAME), "");

  for (i = 0; i < namesLen; i++) {
    Acl_NewPermissionsList("test-whoUses", &permissionsVec);
    Acl_GetUserPermissions(entityManager, AclResourceName, names[i], &permissionsVec);
    len = hcount(permissionsVec->Permissions);
    if (exp[i] != len) {
      printf("testGetCheckWhoUseGetAllPermissions fail number of permission "
             "expected for '%s' was "
             "%d, found: %d\n",
             names[i], exp[i], len);
      Acl_PrintPermissionsList(stdout, "", permissionsVec);
      pass = false;
    }
    Acl_FreePermissionsList(permissionsVec);
    whoUses = hcreate(H_TAB_SIZE);
    Acl_WhoUseAPermission(entityManager, permissions[i], whoUses);
    if (Utils_IsEqualHash(whoUses, expectedUsersName[i]) == false) {
      printf("testGetCheckWhoUseGetAllPermissions fail expected entity names "
             "for who use the "
             "permission '%s' was not matched\n",
             permissions[i]);
      Utils_PrintHash("Expected:", expectedUsersName[i]);
      Utils_PrintHash("Found:", whoUses);
      pass = false;
    }
    hdestroy(whoUses); // its a shellow duplication
  }
  Acl_NewPermissionsList("test", &permissionsVec);
  Acl_GetAllPermissions(entityManager, AclResourceName, permissionsVec);
  len = hcount(permissionsVec->Permissions);
  if (len != namesLen - 1) { // the none entry doesnt have permission
    printf("testGetCheckWhoUseGetAllPermissions fail number of permissions %d "
           "is not as expected %d\n",
           len, namesLen - 1);
    Acl_PrintPermissionsList(stdout, "Full permissions list:", permissionsVec);
    pass = false;
  }
  for (i = 0; i < namesLen; i++) {
    if (permissions[i] != NULL && checkPermissionOfEntry(permissionsVec, permissions[i]) == false) {
      printf("testGetCheckWhoUseGetAllPermissions fail permission '%s' was set "
             "but not found in "
             "the full list permissions\n",
             permissions[i]);
      Acl_PrintPermissionsList(stdout, "Full permissions list:", permissionsVec);
      pass = false;
    }
  }
#ifndef MBED_OS
  FILE *devNull = fopen("/dev/null", "w");
  Acl_Print(devNull, "Test acl:", acl);
  fclose(devNull);
#endif
  Acl_FreePermissionsList(permissionsVec);
  for (i = 0; i < namesLen; i++) {
    Utils_FreeHashKeys(expectedUsersName[i]);
  }
  EntityManager_FreeAll(entityManager);
  return pass;
}

STATIC bool testAclCorners() {
  int16_t i = 0, namesLen = -1;
  bool pass = true;
  char *names[3] = { ALL_ACL_NAME, ACL_ENTRY_NAME, BOTH_ENTRY_NAME }, *permission = "add";
  AclPermissionsS *aclEntry;
  AclS *acl;
  void *a;
  EntityManager e1, *entityManager = NULL;

  namesLen = sizeof(names) / sizeof(char *);
  Acl_NewPermissionsList("test", &aclEntry);
  if (updateEntryPermissions(aclEntry, NULL) == true || updateEntryPermissions(NULL, &aclEntry) == true) {
    printf("testAclCorners fail updateEntryPermissions with NULL return successfully\n");
    pass = false;
  }

  EntityManager_New(&e1);
  entityManager = &e1;
  setup(entityManager, namesLen, names);
  EntityManager_GetProperty(entityManager, AclResourceName, ACL_PROPERTY_NAME, &a);
  acl = (AclS *)a;
  for (i = 0; i < namesLen; i++) {
    if (Acl_RemoveEntry(a, names[i]) == false) {
      printf("testAclCorners fail testAclCorners failed to removed entry '%s' from ACL\n", names[i]);
      pass = false;
    }
    if (Acl_RemoveEntry(a, names[i]) == true || Acl_RemoveEntry(a, NULL) == true) {
      printf("testAclCorners fail testAclCorners removed successfully already removed entry '%s' from ACL\n", names[i]);
      pass = false;
    }
  }
  if (addEntry(acl, NULL, &aclEntry) == true) {
    printf("testAclCorners fail testAclCorners: Successfully add entry to NULL entry name\n");
    pass = false;
  }
  if (Acl_AddPermissionToResource(entityManager, NULL, AclResourceName, permission) == true ||
      Acl_AddPermissionToResource(NULL, AclResourceName, NULL, permission) == true) {
    printf("testAclCorners fail testAclCorners: Successfully add permission to NULL ACL or resource name\n");
    pass = false;
  }
  EntityManager_AddGroup(entityManager, names[1]);
  if (Acl_AddPermissionToResource(entityManager, AclResourceName, names[1], permission) == false) {
    printf("testAclCorners fail testAclCorners: error while add permission to resource, error: %s\n", errStr);
    pass = false;
  }
  if (Acl_RemovePermissionFromResource(entityManager, NULL, AclResourceName, permission) == true ||
      Acl_RemovePermissionFromResource(NULL, AclResourceName, names[0], permission) == true) {
    printf("testAclCorners fail testAclCorners: Successfully remove permission from NULL ACL or resource "
           "name\n");
    pass = false;
  }
  EntityManager_FreeAll(entityManager);
  Acl_FreePermissionsList(aclEntry);
  Acl_Free(NULL);
  Acl_FreePermissionsList(NULL);
  return pass;
}

// Verify that stored ACL is equal to the loaded one
STATIC bool testStoreLoadAcl() {
  bool pass = true;
  char *prefix = "test-acl", *tName = NULL;
  SecureStorageS storage;
  int16_t i = 0, namesLen = -1;
  char *names[3] = { ALL_ACL_NAME, ACL_ENTRY_NAME, BOTH_ENTRY_NAME };
  char *permission = "add";
  EntityManager e1, *entityManager = NULL;
  void *a = NULL, *a1 = NULL;
  AclS *acl = NULL;

  namesLen = sizeof(names) / sizeof(char *);
  if (SecureStorage_NewStorage(SECRET, DEFAULT_SALT, &storage) == false) {
    printf("testStoreLoadAcl failed: Error when try to create new storage, "
           "error: %s\n",
           errStr);
    return false;
  }

  EntityManager_New(&e1);
  entityManager = &e1;
  EntityManager_AddGroup(entityManager, BOTH_ENTRY_NAME);
  setup(entityManager, namesLen, names);
  EntityManager_AddUserToGroup(entityManager, BOTH_ENTRY_NAME, ACL_ENTRY_NAME);
  if (EntityManager_GetProperty(entityManager, AclResourceName, ACL_PROPERTY_NAME, &a) == false) {
    printf("Error: Can't get ACL property from '%s'\n", names[i]);
    return false;
  }
  acl = (AclS *)a;
  for (i = 0; i < namesLen; i++) {
    addPermissionToResource(acl, names[i], permission);
  }
  if (Acl_Store(acl, &storage, prefix) == false) {
    printf("testStoreLoadAcl failed: Error when try to store ACL to "
           "storage, error: %s\n",
           errStr);
    pass = false;
  }
  if (Acl_Load((void **)(&a1), NULL, prefix, &tName) == true) {
    printf("testStoreLoadAcl failed: successfully load from NULL strorage\n");
    pass = false;
  }
  if (Acl_Load((void **)(&a1), &storage, prefix, &tName) == false) {
    printf("testStoreLoadAcl failed: Error when try to load ACL from "
           "storage, error: %s\n",
           errStr);
    pass = false;
  } else if (Acl_IsEqual(a, a1) == false) {
    printf("testStoreLoadAcl failed: stored and loaded ACLs are not equal, error: %s\n", errStr);
    Acl_Print(stdout, "Acl1:\n", a);
    Acl_Print(stdout, "Acl2:\n", a1);
    pass = false;
  }
  SecureStorage_FreeStorage(&storage);
  EntityManager_FreeAll(&e1);
  Acl_Free(a1);
  return pass;
}

#ifdef MBED_OS
int16_t testAcl()
#else
int main()
#endif
{
  bool pass = true;
  Acl_TestMode = true;
  int16_t i = 0, len = 0;
  char *res = NULL;

  Acl_TestMode = true;
  AclEntry_TestMode = true;

  Utils_TestFuncS callFunc[] = { { "testAddPermission", testAddPermission },
                                 { "testAddRemoveCheckPermission", testAddRemoveCheckPermission },
                                 { "testGetCheckWhoUseGetAllPermissions", testGetCheckWhoUseGetAllPermissions },
                                 { "testStoreLoadAcl", testStoreLoadAcl },
                                 { "testAclCorners", testAclCorners } };

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
