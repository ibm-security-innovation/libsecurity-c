// Package acl : Access Control List (ACL) package provides all the ACL services including the definition and control of resource
// permissions.
// The implementation should allow flexible types of access tAco resources (not limited to READ/WRITE/EXECUTE)
//
// The ACL property structure:
// An ACL has a list of entries. Each ACL Entry consists of the following fields:
// - An Entry name (obligatory, must be the name of an entity from the entity list)
// - List of permissions (optional)
//
//  A user has a given permission to the entity if:
//    1. The user name is equal to the Entry name and the permissions list of the relevant Entry grants that permission
//    2. The Entry is a name of entity (group) that the user is member of and the permissions list of the relevant Entry grants that
//    permission
//    3. The 'All' Entry grants that permission
// Notes:
//    1. Group of groups are not handled
//    2. If User1 is removed from the Entity list and then re added,
//  the only permission it will initially have is the 'All' permissions.
//  This is because a removed entity cannot be re-added,
//  but a new entity with its name can be created.
//  In this case, the new Entity User1 may be of a different user than the one that originally received the permissions.
//
// Example:
// If the Entity list is:
//  Name: User1
//  Name: IBM, members: User2, User3
//  Name: All (reserved token)
//  Name: Disk, properties: ACL:
//  ACL → Name: User1, properties: “can write”, “Can take”
//    Name: IBM, properties: “can read”
//    Name: All, Properties: “Execute”
//
// In this example:
//  1.The user-entity named User1 has the following permissions with relation to the resource-entity Disk: “can write”, “Can take” and
//  “Execute” (via All)
//  2.The group-entity named IBM has the following permissions with relation to the resource-entity Disk: “can read” and “Execute” (via All)
//  3.The user-entity named User2 has the following permissions with relation to the resource-entity Disk: “can read” (via IBM) and
//  “Execute” (via All)
//
// Entity Structure:
//  Entity =======> ACL |===========> Entry
//                      |===========> Entry
//                      |===========> Entry
// Entry structure:
//  Entry  =======> name (entity name)
//         |======> list of permissions
//

#include "libsecurity/acl/acl_int.h"

bool Acl_TestMode = false;

void Acl_Print(FILE *ofp, const char *prefix, const void *a) {
  const AclS *acl = NULL;
  AclPermissionsS *aclEntry = NULL;
  htab *t = NULL;

  if (prefix != NULL) fprintf(ofp, "%s", prefix);
  if (a == NULL) return;
  acl = (const AclS *)a;
  t = acl->Entries;
  fprintf(ofp, "Acl: ");
  if (hfirst(t)) {
    do {
      if (getEntry(acl, (char *)hkey(t), &aclEntry) == true) {
        fprintf(ofp, "Entry name '%s'\n", (char *)hkey(t));
        Acl_PrintPermissionsList(ofp, "", (void *)hstuff(t));
      }
    } while (hnext(t));
    fprintf(ofp, "\n");
  } else
    fprintf(ofp, "no permissions are set to the entity\n");
}

void Acl_PrintPermissionsList(FILE *ofp, const char *prefix, const void *a) {
  const AclPermissionsS *aclEntry = NULL;
  htab *t = NULL;

  if (prefix != NULL) fprintf(ofp, "%s", prefix);
  if (a == NULL) return;
  aclEntry = (const AclPermissionsS *)a;
  t = aclEntry->Permissions;
  if (hfirst(t)) {
    fprintf(ofp, "Permissions: ");
    do {
      fprintf(ofp, "%s, ", (char *)hkey(t));
    } while (hnext(t));
    fprintf(ofp, "\n");
  } else
    fprintf(ofp, "No permissions are set to the entity\n");
}

bool Acl_New(AclS **acl) {
  Utils_Malloc((void **)(acl), sizeof(AclS) + 1);
  (*acl)->Entries = hcreate(H_TAB_SIZE);
  EntityManager_RegisterPropertyHandleFunc(ACL_PROPERTY_NAME, Acl_Free, Acl_Store, Acl_Load, Acl_Print, Acl_IsEqual);
  return true;
}

bool Acl_NewPermissionsList(const char *entityName, AclPermissionsS **aclEntry) {
  char *nameStr = NULL;

  if (entityName == NULL) return false;
  Utils_Malloc((void **)(aclEntry), sizeof(AclPermissionsS) + 1);
  Utils_CreateAndCopyString(&nameStr, entityName, strlen(entityName));
  (*aclEntry)->Name = nameStr;
  (*aclEntry)->Permissions = hcreate(H_TAB_SIZE);
  return true;
}

void Acl_Free(void *a) {
  AclS *acl = NULL;
  htab *t = NULL;

  if (a == NULL) {
    return;
  }
  acl = (AclS *)a;
  t = acl->Entries;
  if (hfirst(t)) {
    do {
      Acl_FreePermissionsList(hstuff(t));
      Utils_Free(hkey(t));
    } while (hnext(t));
    hdel(t);
  }
  hdestroy(t);
  Utils_Free(acl);
}

void Acl_FreePermissionsList(void *e) {
  AclPermissionsS *aclEntry = NULL;
  htab *t = NULL;

  if (e == NULL) {
    return;
  }
  aclEntry = (AclPermissionsS *)e;
  t = aclEntry->Permissions;
  if (hfirst(t)) {
    do {
      Utils_Free(hkey(t));
    } while (hnext(t));
    hdel(t);
  }
  hdestroy(t);
  Utils_Free(aclEntry->Name);
  Utils_Free(aclEntry);
}

bool Acl_RemoveEntry(void *a, const char *entryName) {
  htab *t = NULL;
  AclS *acl;

  if (a == NULL) {
    snprintf(errStr, sizeof(errStr), "can't remove entry from free NULL ACL");
    return false;
  }
  if (entryName == NULL) {
    snprintf(errStr, sizeof(errStr), "can't remove NULL entry name from ACL");
    return false;
  }
  acl = (AclS *)a;
  t = acl->Entries;
  if (hfind(t, (const ub1 *)entryName, (ub4)strlen(entryName)) == true) {
    Utils_Free(hkey(t));
    Acl_FreePermissionsList(hstuff(t));
    hdel(t);
    return true;
  }
  return false;
}

STATIC bool isItAllEntry(const char *name) {
  if (name == NULL) {
    assert(LIB_NAME "Name string must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  return (name != NULL && strcmp(name, ALL_ACL_NAME) == 0);
}


STATIC bool getEntry(const AclS *acl, const char *name, AclPermissionsS **aclEntry) {
  htab *t = NULL;

  if (acl == NULL || name == NULL) {
    assert(LIB_NAME "Acl structure and name string must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  t = acl->Entries;
  if (hfind(t, (const ub1 *)name, (ub4)strlen(name)) == true) {
    *aclEntry = (AclPermissionsS *)hstuff(t);
    return true;
  }
  return false;
}

STATIC bool addEntry(AclS *acl, const char *entityName, AclPermissionsS **aclEntry) {
  char *nameStr = NULL;

  if (acl == NULL) {
    assert(LIB_NAME "Acl structure must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  if (entityName == NULL) {
    snprintf(errStr, sizeof(errStr), "can't add NULL entity name to ACL");
    assert(LIB_NAME "Entity name string must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  if (Acl_NewPermissionsList(entityName, aclEntry) == false) {
    snprintf(errStr, sizeof(errStr), "creating new entry fail");
    return false;
  }
  if (hadd(acl->Entries, (const ub1 *)entityName, (ub4)strlen(entityName), aclEntry) == true) {
    Utils_CreateAndCopyString(&nameStr, entityName, strlen(entityName));
    hkey(acl->Entries) = (unsigned char *)nameStr;
    hstuff(acl->Entries) = *aclEntry;
  }
  return true;
}

STATIC bool addPermissionToResource(AclS *acl, const char *entityName, const char *permission) {
  AclPermissionsS *aclEntry = NULL;

  if (acl == NULL || entityName == NULL || permission == NULL) {
    snprintf(errStr, sizeof(errStr), "Acl, entity name, Acl and permission must not be NULL");
    assert(LIB_NAME "Acl structure, entityName string and permission string must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  if (getEntry(acl, entityName, &aclEntry) == false) {
    if (hcount(acl->Entries) >= MAX_NUMBER_OF_USERS_IN_ACL) {
      snprintf(errStr, sizeof(errStr), "can't add the new permission to entity '%s', the ACL already "
                                       "have the maximum number of entries %d",
               permission, MAX_NUMBER_OF_USERS_IN_ACL);
      return false;
    }
    addEntry(acl, entityName, &aclEntry);
  }
  return addPermissionToEntry(aclEntry, permission);
}

STATIC bool addPermissionToResourceHandler(const EntityManager *entityManager, const char *resourceName, const char *entityName, const char *permission) {
  AclS *acl = NULL;

  if (resourceName == NULL || entityName == NULL || permission == NULL || entityManager == NULL) {
    snprintf(errStr, sizeof(errStr), "Acl, entity name, entityManager and permission must not be NULL");
    assert(LIB_NAME "EntityManager structure, resourceName, entityName and permission strings must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  if (EntityManager_GetProperty(entityManager, resourceName, ACL_PROPERTY_NAME, (void **)(&acl)) == false) {
    printf("Error: the resource '%s' doesn't have ACL property\n", resourceName);
    return false;
  }
  if (EntityManager_IsEntityInUsersList(entityManager, entityName) == false && EntityManager_IsEntityInGroupsList(entityManager, entityName) == false) {
    snprintf(errStr, sizeof(errStr), "The entity '%s' must be added to the entity manager first", entityName);
    return false;
  }
  return addPermissionToResource(acl, entityName, permission);
}

bool Acl_AddPermissionToResource(const EntityManager *entityManager, const char *resourceName, const char *entityName, const char *permission) {
  if (resourceName == NULL || entityName == NULL || permission == NULL || entityManager == NULL) {
    snprintf(errStr, sizeof(errStr), "Acl, entity name, entityManager and permission must not be NULL");
    return false;
  }
  return addPermissionToResourceHandler(entityManager, resourceName, entityName, permission);
}

bool Acl_RemovePermissionFromResource(const EntityManager *entityManager, const char *resourceName, const char *entityName, const char *permission) {
  AclPermissionsS *aclEntry = NULL;
  AclS *acl = NULL;

  if (entityManager == NULL || resourceName == NULL || entityName == NULL || permission == NULL) {
    snprintf(errStr, sizeof(errStr), "Acl, entity name and permission must not be NULL");
    return false;
  }
  if (EntityManager_GetProperty(entityManager, resourceName, ACL_PROPERTY_NAME, (void **)(&acl)) == false) {
    printf("Error: the resource '%s' doesn't have ACL property\n", resourceName);
    return false;
  }
  if (getEntry(acl, entityName, &aclEntry) == false) {
    snprintf(errStr, sizeof(errStr), "resource doesn't have permission aclaclEntryS for '%s'", entityName);
    return false;
  }
  return removePermissionFromEntry(aclEntry, permission);
}

// Return all the permissions that are associated with the given resource
bool Acl_GetAllPermissions(const EntityManager *entityManager, const char *resourceName, AclPermissionsS *pEntry) {
  AclPermissionsS *aclEntry = NULL;
  AclS *acl = NULL;
  htab *t = NULL;

  if (resourceName == NULL || entityManager == NULL || pEntry == NULL) return false;
  if (EntityManager_GetProperty(entityManager, resourceName, ACL_PROPERTY_NAME, (void **)(&acl)) == false) {
    printf("Error: the resource '%s' doesn't have ACL property\n", resourceName);
    return false;
  }
  t = acl->Entries;
  if (hfirst(t)) {
    do {
      if (getEntry(acl, (char *)hkey(t), &aclEntry) == true) {
        updateEntryPermissions(aclEntry, &pEntry);
      }
    } while (hnext(t));
  }
  return true;
}

// Get all the permissions of a given user to a given resource-
// return the user's list of permissions to the given resource
// The permissions may be listed as the user's permissions, permissions to
// groups
// in which the user is a member or permissions that are given to 'all'
bool Acl_GetUserPermissions(const EntityManager *entityManager, const char *resourceName, const char *userName, AclPermissionsS **pEntry) {
  AclPermissionsS *aclEntry = NULL;
  AclS *acl = NULL;
  htab *t = NULL;
  if (resourceName == NULL || userName == NULL || entityManager == NULL || pEntry == NULL || *pEntry == NULL) return false;
  if (EntityManager_GetProperty(entityManager, resourceName, ACL_PROPERTY_NAME, (void **)(&acl)) == false) {
    printf("Error: the resource '%s' doesn't have ACL property\n", resourceName);
    return false;
  }
  if (EntityManager_IsEntityInUsersList(entityManager, userName) == false && EntityManager_IsEntityInGroupsList(entityManager, userName) == false)
    return true;
  t = acl->Entries;
  if (hfirst(t)) {
    do {
      if (getEntry(acl, (char *)hkey(t), &aclEntry) == false) continue;
      if (isItAllEntry(aclEntry->Name) || strcmp(aclEntry->Name, userName) == 0 ||
          EntityManager_IsUserPartOfAGroup(entityManager, aclEntry->Name, userName) == true) {
        updateEntryPermissions(aclEntry, pEntry);
      }
    } while (hnext(t));
  }
  return true;
}

// Checks if the given entity has a given permission to the resource
bool Acl_CheckEntityPermission(const EntityManager *entityManager, const char *resourceName, const char *userName, const char *permission) {
  bool ret = false;
  AclS *acl = NULL;
  AclPermissionsS *pEntry = NULL;

  if (resourceName == NULL || userName == NULL || permission == NULL || entityManager == NULL) return false;
  if (EntityManager_GetProperty(entityManager, resourceName, ACL_PROPERTY_NAME, (void **)(&acl)) == false) {
    printf("Error: the resource '%s' doesn't have ACL property\n", resourceName);
    return false;
  }
  Acl_NewPermissionsList("tmp", &pEntry);
  if (Acl_GetUserPermissions(entityManager, resourceName, userName, &pEntry) == true) {
    ret = checkPermissionOfEntry(pEntry, permission);
  }
  Acl_FreePermissionsList(pEntry);
  return ret;
}

// Return all the users that have the given permission to the given resource
bool Acl_WhoUseAPermission(const EntityManager *entityManager, const char *permission, htab *names) {
  char *entityName = NULL, *resourceName = NULL;
  htab *t = NULL, *entryDup = NULL, *resourceDup = NULL;
  void *a = NULL;
  AclS *acl = NULL;

  if (entityManager == NULL || permission == NULL) return false;
  // I need to duplicate the hash due to the hash implementation that changes the pointers
  resourceDup = hcreate(H_TAB_SIZE);
  Utils_DuplicateHash(entityManager->Resources->Items, resourceDup);
  if (resourceDup != NULL) {
    do {
      resourceName = (char *)hkey(resourceDup);
      if (EntityManager_GetProperty(entityManager, resourceName, ACL_PROPERTY_NAME, &a) == true) {
        acl = (AclS *)a;
        entryDup = hcreate(H_TAB_SIZE);
        Utils_DuplicateHash(acl->Entries, entryDup);
        t = entryDup;
        if (hfirst(t)) {
          do {
            entityName = (char *)hkey(t);
            if (Acl_CheckEntityPermission(entityManager, resourceName, entityName, permission) == true) {
              debug_print("Permission '%s' for '%s' was found\n", permission, entityName);
              if (strcmp(entityName, ALL_ACL_NAME) == 0) {
                Utils_DuplicateHash(entityManager->Users->Items, names);
                Utils_DuplicateHash(entityManager->Groups->Items, names);
              } else if (hadd(names, (const ub1 *)entityName, (ub4)strlen(entityName), "")) {
                hkey(names) = (unsigned char *)entityName;
              }
            }
          } while (hnext(t));
        }
        hdestroy(entryDup);
      }
    } while (hnext(resourceDup));
  }
  hdestroy(resourceDup); // its a shellow duplication
  return true;
}

STATIC bool storeEntry(const void *a, const SecureStorageS *storage, const char *modulePrefix) {
  int16_t cnt = 1, prefixLen = -1;
  char *prefix = NULL, *entryPrefix = NULL;
  char data[MAX_STORE_LOAD_LEN];
  htab *t = NULL;
  const AclPermissionsS *aclEntry = NULL;

  if (a == NULL || storage == NULL || modulePrefix == NULL) {
    assert(LIB_NAME "Acl permission and storage structures as well as module prefix strings must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  if (Utils_IsPrefixValid("storeEntry", modulePrefix) == false) return false;
  aclEntry = (const AclPermissionsS *)a;
  t = aclEntry->Permissions;
  sprintf(data, "%d", (int16_t)hcount(t));

  prefixLen = strlen(modulePrefix) + strlen(ACL_ENTRY_PREFIX) + 1;
  Utils_Malloc((void **)(&prefix), prefixLen);
  snprintf(prefix, prefixLen, ACL_ENTRY_PREFIX_FMT, ACL_ENTRY_PREFIX, modulePrefix);

  if (SecureStorage_AddItem(storage, (const unsigned char *)prefix, strlen(prefix), (unsigned char *)data, strlen(data)) == false) {
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", prefix, data);
    Utils_Free((void *)prefix);
    return false;
  }
  debug_print("Add to storage: num of permissions key: '%s' val '%s'\n", prefix, data);
  if (EntityManager_StoreName(storage, prefix, aclEntry->Name, &entryPrefix) == false) return false;
  Utils_Free(entryPrefix);
  if (hfirst(t)) {
    do {
      snprintf(data, sizeof(data), ACL_ENTRY_KEY_FMT, PERMISSION_PREFIX, prefix, cnt++);
      if (SecureStorage_AddItem(storage, (unsigned char *)data, strlen(data), (unsigned char *)hkey(t), strlen((char *)hkey(t))) == false) {
        snprintf(errStr, sizeof(errStr), "can't add item '%s' value '%s' to storage", data, (char *)hkey(t));
        Utils_Free((void *)prefix);
        return false;
      }
      debug_print("Add to storage: permission key: '%s' val '%s'\n", data, (char *)hkey(t));
    } while (hnext(t));
  }
  Utils_Free((void *)prefix);
  return true;
}

bool Acl_Store(const void *a, const SecureStorageS *storage, const char *modulePrefix) {
  int16_t cnt = 1, prefixLen = -1;
  char *prefix = NULL, data[MAX_STORE_LOAD_LEN];
  htab *t = NULL;
  const AclS *acl = NULL;

  if (a == NULL || storage == NULL || modulePrefix == NULL) return false;
  if (Utils_IsPrefixValid("Acl_Store", modulePrefix) == false) return false;
  acl = (const AclS *)a;
  t = acl->Entries;
  sprintf(data, "%d", (int16_t)hcount(t));
  prefixLen = strlen(modulePrefix) + strlen(ACL_PREFIX) + 1;
  Utils_Malloc((void **)(&prefix), prefixLen);
  snprintf(prefix, prefixLen, ACL_PREFIX_FMT, ACL_PREFIX, modulePrefix);
  if (SecureStorage_AddItem(storage, (const unsigned char *)prefix, strlen(prefix), (unsigned char *)data, strlen(data)) == false) {
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", prefix, data);
    Utils_Free((void *)prefix);
    return false;
  }
  debug_print("Add to storage: num of entries key: '%s' val '%s'\n", prefix, data);
  if (hfirst(t)) {
    do {
      snprintf(data, sizeof(data), ACL_KEY_FMT, ACL_KEY_PREFIX, prefix, cnt++);
      storeEntry((void *)hstuff(t), storage, data);
    } while (hnext(t));
  }
  Utils_Free((void *)prefix);
  return true;
}

STATIC bool loadEntry(AclS *acl, const SecureStorageS *storage, const char *modulePrefix) {
  int16_t i = 0, len = 0, prefixLen = -1;
  char *val = NULL, *prefix = NULL, *name = NULL, *entryPrefix = NULL;
  char key[MAX_STORE_LOAD_LEN];

  if (storage == NULL) {
    snprintf(errStr, sizeof(errStr), "Storage must be intiated first");
    assert(LIB_NAME "Storage structure must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  if (Utils_IsPrefixValid("loadEntry", modulePrefix) == false) {
    assert(LIB_NAME "Module prefix strings must be valid" && (false || Acl_TestMode));
    return false;
  }

  prefixLen = strlen(modulePrefix) + strlen(ACL_ENTRY_PREFIX) + 1;
  Utils_Malloc((void **)(&prefix), prefixLen);
  snprintf(prefix, prefixLen, ACL_ENTRY_PREFIX_FMT, ACL_ENTRY_PREFIX, modulePrefix);

  if (SecureStorage_GetItem(storage, (const unsigned char *)prefix, strlen(prefix), (unsigned char **)&val) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: loadEntry, Read from secure "
                                     "storage key '%s' not found",
             prefix);
    Utils_Free((void *)prefix);
    return false;
  }
  len = atoi(val);
  Utils_Free(val);
  if (len > MAX_NUMBER_OF_USERS_IN_ACL) {
    snprintf(errStr, sizeof(errStr), "Internal Error: read number of entries in "
                                     "ACL %d too large, the maximum number is %d",
             len, MAX_NUMBER_OF_USERS_IN_ACL);
    return false;
  }
  debug_print("read: key: '%s' num of permissions %d\n", prefix, len);
  for (i = 0; i < len; i++) {
    snprintf(key, sizeof(key), ACL_ENTRY_KEY_FMT, PERMISSION_PREFIX, prefix, i + 1);
    if (EntityManager_LoadName(storage, prefix, &name, &entryPrefix) == false) return false;
    if (SecureStorage_GetItem(storage, (unsigned char *)key, strlen(key), (unsigned char **)&val) == false) {
      snprintf(errStr, sizeof(errStr), "Internal Error: aclEntry_loadEntry, Read "
                                       "from secure storage key '%s' not found",
               key);
      Utils_Free(entryPrefix);
      Utils_Free((void *)prefix);
      return false;
    }
    debug_print("read: key: '%s' permission val '%s'\n", key, val);
    if (addPermissionToResource(acl, name, val) == false) {
      printf("Internal error when reading from secure storage: can't add "
             "permission '%s' to '%s'\n",
             val, name);
    }
    Utils_Free(val);
    Utils_Free(name);
    Utils_Free(entryPrefix);
  }
  Utils_Free((void *)prefix);
  return true;
}

bool Acl_Load(void **acl, const SecureStorageS *storage, const char *modulePrefix, char **retName) {
  int16_t i = 0, len = 0, prefixLen = -1;
  char *val = NULL, *prefix = NULL;
  char key[MAX_STORE_LOAD_LEN];

  *retName = NULL;
  if (storage == NULL) {
    snprintf(errStr, sizeof(errStr), "Storage must be intiated first");
    return false;
  }
  if (Utils_IsPrefixValid("Acl_Load", modulePrefix) == false) {
    return false;
  }
  prefixLen = strlen(modulePrefix) + strlen(ACL_PREFIX) + 1;
  Utils_Malloc((void **)(&prefix), prefixLen);
  snprintf(prefix, prefixLen, ACL_PREFIX_FMT, ACL_PREFIX, modulePrefix);
  if (SecureStorage_GetItem(storage, (const unsigned char *)prefix, strlen(prefix), (unsigned char **)&val) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: Acl_Load, Read from secure storage key '%s' not found", prefix);
    Utils_Free((void *)prefix);
    return false;
  }
  len = atoi(val);
  Utils_Free(val);
  Acl_New((AclS **)acl);
  debug_print("read: key: '%s' num of entries %d\n", prefix, len);
  for (i = 0; i < len; i++) {
    snprintf(key, sizeof(key), ACL_KEY_FMT, ACL_KEY_PREFIX, prefix, i + 1);
    if (loadEntry(*acl, storage, key) == false) {
      Utils_Free((void *)prefix);
      return false;
    }
  }
  Utils_Free((void *)prefix);
  return true;
}

bool Acl_IsEqual(const void *a1, const void *a2) {
  const AclS *acl1 = NULL, *acl2 = NULL;
  AclPermissionsS *e1 = NULL, *e2 = NULL;
  htab *p1 = NULL;

  if (a1 == NULL && a2 == NULL) return true;
  if (a1 == NULL || a2 == NULL) return false;
  acl1 = (const AclS *)a1;
  acl2 = (const AclS *)a2;
  p1 = acl1->Entries;
  if (hfirst(p1)) {
    do {
      debug_print("Compare entries '%s'\n", (char *)hkey(p1));
      if (getEntry(acl1, (char *)hkey(p1), &e1) == false) return false;
      if (getEntry(acl2, (char *)hkey(p1), &e2) == false) {
        debug_print("Entry '%s' wasn't found on the second acl\n", (char *)hkey(p1));
        return false;
      }
      if (isEqualEntry((void *)e1, (void *)e2) == false) {
        debug_print("Entry '%s' is not equal\n", (char *)hkey(p1));
        return false;
      }
    } while (hnext(p1));
  }
  return true;
}

STATIC bool isEqualEntry(const void *e1, const void *e2) {
  const AclPermissionsS *aclEntry1 = NULL, *aclEntry2 = NULL;
  htab *p1 = NULL;

  if (e1 == NULL || e2 == NULL) {
    assert(LIB_NAME "AclPermission structures must not be NULL" && (false || Acl_TestMode));
    return false;
  }
  aclEntry1 = (const AclPermissionsS *)e1;
  aclEntry2 = (const AclPermissionsS *)e2;
  // for All and root that may not initated with permissions
  if (aclEntry1->Permissions == NULL && aclEntry2->Permissions == NULL) return true;
  if (strcmp(aclEntry1->Name, aclEntry2->Name) != 0) return false;
  if (aclEntry1->Permissions == NULL || aclEntry2->Permissions == NULL || hcount(aclEntry1->Permissions) != hcount(aclEntry2->Permissions))
    return false;
  p1 = aclEntry1->Permissions;
  if (hfirst(p1)) {
    do {
      debug_print("Compare permission '%s'\n", (char *)hkey(p1));
      if (checkPermissionOfEntry(aclEntry2, (char *)hkey(p1)) == false) {
        debug_print("Permission '%s' wasn't found on the second AclPermissionsS\n", (char *)hkey(p1));
        return false;
      }
    } while (hnext(p1));
  }
  return true;
}
