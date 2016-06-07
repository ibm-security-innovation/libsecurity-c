// Entity : The Entity package includes implementation of User, Group, Resource and a container of all theses entities.
//
// There are three types of entities: User, Group and resource
//  - Users have a name and a list of properties
//  - Groups have a name, list of users associated with it
//    (each user is a name of an existing User entity) and a list of properties
//  - Resources have a name and a list of properties
//
// There is a special group entity, that is not defined explicitly, with the name "All".
//  This entity is used in the ACL when the resource has permission properties that applies to all the entities in the system

#include "libsecurity/entity/entityManager_int.h"
#include "libsecurity/acl/acl.h"

void EntityManager_Print(FILE *ofp, const char *header, const EntityManager *entityManager) {
  htab *t = NULL;

  if (header != NULL) fprintf(ofp, "%s\n", header); // print the header even for NULL items
  if (entityManager == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_Print: entityManager must not be NULL");
    return;
  }
  t = entityManager->Users->Items;
  if (hfirst(t)) {
    do {
      printUser(ofp, "", (void *)hstuff(t));
    } while (hnext(t));
  }
  t = entityManager->Groups->Items;
  if (hfirst(t)) {
    do {
      printGroup(ofp, "", (void *)hstuff(t));
    } while (hnext(t));
  }
  t = entityManager->Resources->Items;
  if (hfirst(t)) {
    do {
      printResource(ofp, "", (void *)hstuff(t));
    } while (hnext(t));
  }
  fprintf(ofp, "\n");
}

// Print all the data include the entity properties
void EntityManager_PrintFull(FILE *ofp, const char *header, const EntityManager *entityManager) {
  htab *t = NULL;

  if (header != NULL) fprintf(ofp, "%s\n", header); // print the header even for NULL items
  if (entityManager == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_PrintFull: entityManager must not be NULL");
    return;
  }
  t = entityManager->Users->Items;
  if (hfirst(t)) {
    do {
      fullPrintUser(ofp, "", (void *)hstuff(t));
    } while (hnext(t));
  }
  t = entityManager->Groups->Items;
  if (hfirst(t)) {
    do {
      fullPrintGroup(ofp, "", (void *)hstuff(t));
    } while (hnext(t));
  }
  t = entityManager->Resources->Items;
  if (hfirst(t)) {
    do {
      fullPrintResource(ofp, "", (void *)hstuff(t));
    } while (hnext(t));
  }
  fprintf(ofp, "\n");
}

STATIC void printUser(FILE *ofp, const char *header, const void *u) {
  fprintf(ofp, "%s", header);
  if (u == NULL) return;
  fprintf(ofp, "***** User name: '%s'\n", ((const userData *)u)->Name);
}

STATIC void printGroup(FILE *ofp, const char *header, const void *u) {
  const groupData *entity = NULL;

  fprintf(ofp, "%s", header);
  if (u == NULL) return;
  entity = (const groupData *)u;
  fprintf(ofp, "***** Group name: '%s'\n", entity->Name);
  fprintf(ofp, "Members: ");
  if (hfirst(entity->Members)) {
    do {
      fprintf(ofp, "'%s', ", (char *)hkey(entity->Members));
    } while (hnext(entity->Members));
  }
  fprintf(ofp, "\n");
}

STATIC void printResource(FILE *ofp, const char *header, const void *u) {
  fprintf(ofp, "%s", header);
  if (u == NULL) return;
  fprintf(ofp, "***** Resource name: '%s'\n", ((const resourceData *)u)->Name);
}

// Print user information include its properties
STATIC void fullPrintUser(FILE *ofp, const char *header, const void *u) {
  const userData *entity = NULL;

  printUser(ofp, header, u);
  if (u == NULL) return;
  entity = (const userData *)u;
  printProperties(ofp, entity->PropertiesData);
}

// Print group information include its properties
STATIC void fullPrintGroup(FILE *ofp, const char *header, const void *u) {
  const groupData *entity = NULL;

  printGroup(ofp, header, u);
  if (u == NULL) return;
  entity = (const groupData *)u;
  printProperties(ofp, entity->PropertiesData);
}

// Print resource information include its properties
STATIC void fullPrintResource(FILE *ofp, const char *header, const void *u) {
  const resourceData *entity = NULL;

  printResource(ofp, header, u);
  if (u == NULL) return;
  entity = (const resourceData *)u;
  printProperties(ofp, entity->PropertiesData);
}

void EntityManager_New(EntityManager *entityManager) {
  if (entityManager == NULL) {
    Utils_Abort("Fatal internal error: call to EntityManager_New with NULL "
                "parameter\n");
  }
  ItemsList_New(&(entityManager->Users));
  ItemsList_New(&(entityManager->Groups));
  ItemsList_New(&(entityManager->Resources));
  EntityManager_AddGroup(entityManager, ALL_ACL_NAME);
  EntityManager_AddUser(entityManager, ROOT_USER_NAME);
}

STATIC bool checkAddValidParams(EntityManager *entityManager, const char *name) {
  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "entityManager (isNull %d) and user name '%s' must not be NULL", entityManager == NULL, name);
    assert(LIB_NAME "EntityManager structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (EntityManager_IsEntityInList(entityManager, name) == true) {
    snprintf(errStr, sizeof(errStr), "the name '%s' is already in the EntityManager", name);
    return false;
  }
  return true;
}

// Add a new User (if the name is not used yet) to the Users list
bool EntityManager_AddUser(EntityManager *entityManager, const char *name) {
  userData *entity = NULL;

  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_AddUser entityManager (isNull %d) and user name '%s' must not be NULL", entityManager == NULL, name);
    return false;
  }
  if (checkAddValidParams(entityManager, name) == false) return false;
  if (newUser(&entity, name) == false) return false;
  if (ItemsList_AddItem(entityManager->Users, name, entity) == false) {
    freeUser(entity);
    return false;
  }
  return EntityManager_AddUserToGroup(entityManager, ALL_ACL_NAME, name);
}

// Add a new Group (if the name is not used yet) to the Groups list
bool EntityManager_AddGroup(EntityManager *entityManager, const char *name) {
  groupData *entity = NULL;

  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_AddGroup entityManager (isNull %d) and user name '%s' must not be NULL", entityManager == NULL, name);
    return false;
  }
  if (checkAddValidParams(entityManager, name) == false) return false;
  if (newGroup(&entity, name) == false) return false;
  if (ItemsList_AddItem(entityManager->Groups, name, entity) == false) {
    freeGroup(entity);
    return false;
  }
  return true;
}

// Add a new Resource (if the name is not used yet) to the Resources list
// Add ACL to the resource
bool EntityManager_AddResource(EntityManager *entityManager, const char *name) {
  resourceData *entity = NULL;
  AclS *acl = NULL;

  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_AddResource entityManager (isNull %d) and user name '%s' must not be NULL",
             entityManager == NULL, name);
    return false;
  }
  if (checkAddValidParams(entityManager, name) == false) return false;
  if (newResource(&entity, name) == false) return false;
  if (ItemsList_AddItem(entityManager->Resources, name, entity) == false) {
    freeGroup(entity);
    return false;
  }
  Acl_New(&acl);
  EntityManager_RegisterProperty(entityManager, name, ACL_PROPERTY_NAME, (void *)acl);
  return true;
}

STATIC bool getGroup(const EntityManager *entityManager, const char *name, void **item) {
  if (entityManager == NULL || name == NULL) {
    assert(LIB_NAME "EntityManager structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  return ItemsList_GetItem(entityManager->Groups, name, item);
}

STATIC bool getUser(const EntityManager *entityManager, const char *name, void **item) {
  if (entityManager == NULL) {
    assert(LIB_NAME "EntityManager structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  return ItemsList_GetItem(entityManager->Users, name, item);
}

STATIC bool getResource(const EntityManager *entityManager, const char *name, void **item) {
  if (entityManager == NULL) {
    assert(LIB_NAME "EntityManager structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  return ItemsList_GetItem(entityManager->Resources, name, item);
}

bool EntityManager_IsEntityInUsersList(const EntityManager *entityManager, const char *name) {
  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_IsEntityInUsersList: entityManager structure and user name string must not be NULL");
    return false;
  }
  return ItemsList_CheckItem(entityManager->Users, name);
}

bool EntityManager_IsEntityInGroupsList(const EntityManager *entityManager, const char *name) {
  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_IsEntityInUGroupsList: entityManager structure and group name string must not be NULL");
    return false;
  }
  return ItemsList_CheckItem(entityManager->Groups, name);
}
bool EntityManager_IsEntityInResourcesList(const EntityManager *entityManager, const char *name) {
  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr),
             "EntityManager_IsEntityInResourcesList: entityManager structure and resource name string must not be NULL");
    return false;
  }
  return ItemsList_CheckItem(entityManager->Resources, name);
}

bool EntityManager_IsEntityInList(const EntityManager *entityManager, const char *name) {
  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_IsEntityInList: entityManager structure and entity name string must not be NULL");
    return false;
  }
  if (Utils_CheckNameValidity("EntityManager_IsEntityInList", name, MIN_ENTITY_NAME_LEN, MAX_ENTITY_NAME_LEN) == false) return false;
  return EntityManager_IsEntityInUsersList(entityManager, name) || EntityManager_IsEntityInGroupsList(entityManager, name) ||
         EntityManager_IsEntityInResourcesList(entityManager, name);
}

STATIC bool checkDataAndGetGroup(const EntityManager *entityManager, const char *groupName, const char *userName, groupData **gEntity) {
  if (entityManager == NULL) {
    snprintf(errStr, sizeof(errStr), "entityManager must not be NULL");
    assert(LIB_NAME "EntityManager structure must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (EntityManager_IsEntityInGroupsList(entityManager, groupName) == false) {
    snprintf(errStr, sizeof(errStr), "group '%s' is not in groups list", groupName);
    return false;
  }
  if (EntityManager_IsEntityInUsersList(entityManager, userName) == false) {
    snprintf(errStr, sizeof(errStr), "user '%s' is not in users list", userName);
    return false;
  }
  if (getGroup(entityManager, groupName, (void **)gEntity) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: EntityManager_AddUserToGroup: can't get group "
                                     "'%s' is from Groups list",
             userName);
    return false;
  }
  return true;
}

bool EntityManager_AddUserToGroup(EntityManager *entityManager, const char *groupName, const char *userName) {
  groupData *gEntity = NULL;

  if (entityManager == NULL || groupName == NULL || userName == NULL) {
    snprintf(errStr, sizeof(errStr),
             "EntityManager_AddUserToGroup entityManager structure (isNull %d) and user name '%s', group name '%s' must not be NULL",
             entityManager == NULL, userName, groupName);
    return false;
  }
  if (checkDataAndGetGroup(entityManager, groupName, userName, &gEntity) == false) {
    return false;
  }
  return addUserToGroup(gEntity, userName);
}

bool EntityManager_RemoveUserFromGroup(EntityManager *entityManager, const char *groupName, const char *userName) {
  groupData *gEntity = NULL;

  if (entityManager == NULL || groupName == NULL || userName == NULL) {
    snprintf(errStr, sizeof(errStr),
             "EntityManager_RemoveUserFromGroup entityManager structure (isNull %d) and user name '%s', group name '%s' must not be NULL",
             entityManager == NULL, userName, groupName);
    return false;
  }
  if (checkDataAndGetGroup(entityManager, groupName, userName, &gEntity) == false) {
    return false;
  }
  return removeAUserFromGroup(gEntity, userName);
}

bool EntityManager_IsUserPartOfAGroup(const EntityManager *entityManager, const char *groupName, const char *userName) {
  groupData *gEntity = NULL;

  if (entityManager == NULL || groupName == NULL || userName == NULL) {
    snprintf(errStr, sizeof(errStr),
             "EntityManager_IsUserPartOfAGroup entityManager structure (isNull %d) and user name '%s', group name '%s' must not be NULL",
             entityManager == NULL, userName, groupName);
    return false;
  }
  if (checkDataAndGetGroup(entityManager, groupName, userName, &gEntity) == false) {
    return false;
  }
  return isUserPartOfGroup(gEntity, userName);
}

STATIC bool removeUserFromAllGroups(EntityManager *entityManager, const char *name) {
  htab *t = NULL;
  groupData *g = NULL;

  if (entityManager == NULL || name == NULL) {
    assert(LIB_NAME "EntityManager structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  t = entityManager->Groups->Items;
  if (hfirst(t)) {
    do {
      g = (groupData *)hstuff(t);
      EntityManager_RemoveUserFromGroup(entityManager, g->Name, name);
    } while (hnext(t));
  }
  return true;
}

STATIC bool removeUserFromAllResources(EntityManager *entityManager, const char *name) {
  htab *t = NULL;
  resourceData *r = NULL;
  void *a = NULL;

  if (entityManager == NULL || name == NULL) {
    assert(LIB_NAME "EntityManager structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  t = entityManager->Resources->Items;
  if (hfirst(t)) {
    do {
      r = (resourceData *)hstuff(t);
      if (EntityManager_GetProperty(entityManager, r->Name, ACL_PROPERTY_NAME, &a) == true) {
        Acl_RemoveEntry(a, name);
      }
    } while (hnext(t));
  }
  return true;
}

bool EntityManager_RemoveUser(EntityManager *entityManager, const char *name) {
  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_RemoveUser: entityManager structure and user name must not be NULL");
    return false;
  }
  removeUserFromAllGroups(entityManager, name);
  removeUserFromAllResources(entityManager, name);
  return ItemsList_ClearItem(freeUser, entityManager->Users, name);
}

bool EntityManager_RemoveGroup(EntityManager *entityManager, const char *name) {
  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_RemoveGroup: entityManager structure and group name must not be NULL");
    return false;
  }
  return ItemsList_ClearItem(freeGroup, entityManager->Groups, name);
}

bool EntityManager_RemoveResource(EntityManager *entityManager, const char *name) {
  if (entityManager == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_RemoveResource: entityManager structure and resource name must not be NULL");
    return false;
  }
  return ItemsList_ClearItem(freeResource, entityManager->Resources, name);
}

bool EntityManager_Free(EntityManager *entityManager, const char *entityName) {
  if (entityManager == NULL || entityName == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_Free: entityManager structure and entity name must not be NULL");
    return false;
  }
  if (EntityManager_RemoveUser(entityManager, entityName) == true) return true;
  if (EntityManager_RemoveGroup(entityManager, entityName) == true) return true;
  return EntityManager_RemoveResource(entityManager, entityName);
}

bool EntityManager_IsEqual(const EntityManager *entityManager1, const EntityManager *entityManager2) {
  if (entityManager1 == NULL && entityManager2 == NULL) return true;
  if (entityManager1 == NULL || entityManager2 == NULL) return false;
  return ItemsList_IsEqual(isEqualUsers, entityManager1->Users, entityManager2->Users) &&
         ItemsList_IsEqual(isEqualGroups, entityManager1->Groups, entityManager2->Groups);
  ItemsList_IsEqual(isEqualResources, entityManager1->Resources, entityManager2->Resources);
}

bool EntityManager_FreeAll(EntityManager *entityManager) {
  if (entityManager == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_FreeAll: entityManager must not be NULL");
    return false;
  }
  ItemsList_FreeAllItems(freeUser, entityManager->Users);
  ItemsList_FreeAllItems(freeGroup, entityManager->Groups);
  ItemsList_FreeAllItems(freeResource, entityManager->Resources);
  entityManager = NULL;
  return true;
}

bool EntityManager_StoreName(const SecureStorageS *storage, const char *modulePrefix, const char *name, char **prefix) {
  int16_t prefixLen = 0;
  char data[MAX_ENTITY_NAME_LEN];

  if (storage == NULL || modulePrefix == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "storeName: storage, prefix and name must not be NULL");
    return false;
  }
  prefixLen = strlen(modulePrefix) + strlen(ENTITY_NAME_POSTFIX) + 1;
  Utils_Malloc((void **)(prefix), prefixLen);
  snprintf(*prefix, prefixLen, ENTITY_NAME_FMT, modulePrefix, ENTITY_NAME_POSTFIX);
  snprintf(data, sizeof(data), ENTITY_STORE_FMT, name);
  if (SecureStorage_AddItem(storage, (unsigned char *)*prefix, strlen(*prefix), (unsigned char *)data, strlen(data)) == false) {
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", *prefix, data);
    Utils_Free((void *)*prefix);
    return false;
  }
  debug_print("Add to storage: key: '%s' val '%s'\n", *prefix, data);
  return true;
}

bool EntityManager_LoadName(const SecureStorageS *storage, const char *modulePrefix, char **name, char **prefix) {
  int16_t prefixLen = -1;

  if (storage == NULL || modulePrefix == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_LoadName: storage and prefix must not be NULL");
    return false;
  }
  prefixLen = strlen(modulePrefix) + strlen(ENTITY_NAME_POSTFIX) + 1;
  Utils_Malloc((void **)(prefix), prefixLen);
  snprintf(*prefix, prefixLen, ENTITY_NAME_FMT, modulePrefix, ENTITY_NAME_POSTFIX);
  if (SecureStorage_GetItem(storage, (unsigned char *)*prefix, strlen(*prefix), (unsigned char **)name) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: Read from secure storage key '%s' not found", *prefix);
    Utils_Free((void *)*prefix);
    return false;
  }
  debug_print("read: key: '%s' entity name '%s'\n", *prefix, *name);
  return true;
}

bool EntityManager_Store(const EntityManager *entityManager, const char *fileName, const unsigned char *secret, const unsigned char *salt) {
  bool ret = true;
  SecureStorageS storage;

  if (entityManager == NULL || fileName == NULL || secret == NULL || salt == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_Store: entityManager structure, file name, secret and salt strings must not be NULL");
    return false;
  }
  if (SecureStorage_NewStorage(secret, salt, &storage) == false) return false;
  ret = ItemsList_AddToStorage(storeUsers, entityManager->Users, &storage, USER_PREFIX);
  ret = ret && ItemsList_AddToStorage(storeGroups, entityManager->Groups, &storage, GROUP_PREFIX);
  ret = ret && ItemsList_AddToStorage(storeResources, entityManager->Resources, &storage, RESOURCE_PREFIX);
  if (ret) {
    ret = ret && SecureStorage_StoreSecureStorageToFile(fileName, &storage);
  }
  SecureStorage_FreeStorage(&storage);
  return ret;
}

bool EntityManager_Load(EntityManager **entityManager, const char *fileName, const unsigned char *secret, const unsigned char *salt) {
  bool ret = false;
  SecureStorageS storage;

  if (entityManager == NULL || *entityManager == NULL || fileName == NULL || secret == NULL || salt == NULL) {
    snprintf(errStr, sizeof(errStr), "EntityManager_Store: entityManager structure, file name, secret and salt strings must not be NULL");
    return false;
  }
  EntityManager_Free(*entityManager, ROOT_USER_NAME);
  EntityManager_Free(*entityManager, ALL_ACL_NAME);
  if (SecureStorage_LoadSecureStorageFromFile(fileName, secret, salt, &storage) == false) {
    return false;
  }
  ret = ItemsList_LoadFromStorage(load, &((*entityManager)->Users), &storage, USER_PREFIX, freeUser);
  ret = ret && ItemsList_LoadFromStorage(load, &((*entityManager)->Groups), &storage, GROUP_PREFIX, freeGroup);
  ret = ret && ItemsList_LoadFromStorage(load, &((*entityManager)->Resources), &storage, RESOURCE_PREFIX, freeResource);
  SecureStorage_FreeStorage(&storage);
  return ret;

  //	return ItemsList_Load(Load, entityManager, fileName, secret, free);
}

STATIC bool getEntity(EntityManager *entityManager, const char *entityName, void **entity) {
  if (entityManager == NULL || entityName == NULL) {
    assert(LIB_NAME "EntityManager structure and entityName string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (EntityManager_IsEntityInUsersList(entityManager, entityName) == true) {
    getUser(entityManager, entityName, entity);
  } else if (EntityManager_IsEntityInGroupsList(entityManager, entityName) == true) {
    getGroup(entityManager, entityName, entity);
  } else if (EntityManager_IsEntityInResourcesList(entityManager, entityName) == true) {
    getResource(entityManager, entityName, entity);
  } else {
    snprintf(errStr, sizeof(errStr), "EntityManager: getEntity: entity '%s' is not in entityManager", entityName);
    return false;
  }
  return true;
}

bool EntityManager_RegisterProperty(EntityManager *entityManager, const char *entityName, const char *propertyName, void *itemData) {
  void *entity = NULL;

  if (entityManager == NULL || propertyName == NULL || entityName == NULL || itemData == NULL) {
    if (Entity_TestMode == false) {
      snprintf(errStr, sizeof(errStr), "Internal error in EntityManager_RegisterProperty: entityManager, property "
                                       "name '%s' entityName and data must not be NULL\n",
               propertyName);
      Utils_Abort(errStr);
    } else
      return false;
  }
  if (getEntity(entityManager, entityName, &entity) == false) {
    snprintf(errStr, sizeof(errStr), "EntityManager_RegisterProperty: entity '%s' is not in entityManager", entityName);
    return false;
  }
  debug_print("Add property '%s'\n", propertyName);
  if (EntityManager_IsEntityInUsersList(entityManager, entityName) == true)
    return ItemsList_AddItem(((userData *)entity)->PropertiesData, propertyName, itemData);
  else if (EntityManager_IsEntityInGroupsList(entityManager, entityName) == true)
    return ItemsList_AddItem(((groupData *)entity)->PropertiesData, propertyName, itemData);
  else if (EntityManager_IsEntityInResourcesList(entityManager, entityName) == true)
    return ItemsList_AddItem(((resourceData *)entity)->PropertiesData, propertyName, itemData);
  return false;
}

bool EntityManager_RegisterPropertyHandleFunc(const char *propertyName, void (*removeItem)(void *item),
                                              bool (*storeItem)(const void *u, const SecureStorageS *storage, const char *prefix),
                                              bool (*loadItem)(void **u, const SecureStorageS *storage, const char *prefix, char **retName),
                                              void (*printItem)(FILE *ofp, const char *header, const void *p),
                                              bool (*isEqual)(const void *entity1, const void *entity2)) {
  return registerPropertyHandleFunc(propertyName, removeItem, storeItem, loadItem, printItem, isEqual);
}

void EntityManager_RemoveRegisteredPropertyList(void) {
  removeRegisteredPropertyList();
}

bool EntityManager_RemoveProperty(EntityManager *entityManager, const char *entityName, const char *propertyName, bool standAlone) {
  void *entity = NULL;

  if (entityManager == NULL || propertyName == NULL || entityName == NULL) {
    if (Entity_TestMode == false) {
      snprintf(errStr, sizeof(errStr), "Internal error in EntityManager_RemoveProperty: entityManager, property "
                                       "name '%s' and entityName must not be NULL\n",
               propertyName);
      Utils_Abort(errStr);
    } else
      return false;
  }
  getEntity(entityManager, entityName, &entity);
  if (entity == NULL) return false;
  if (EntityManager_IsEntityInUsersList(entityManager, entityName) == true)
    return removeProperty((void *)(((userData *)entity)->PropertiesData), propertyName, standAlone);
  else if (EntityManager_IsEntityInGroupsList(entityManager, entityName) == true)
    return removeProperty((void *)(((groupData *)entity)->PropertiesData), propertyName, standAlone);
  else if (EntityManager_IsEntityInResourcesList(entityManager, entityName) == true)
    return removeProperty((void *)(((resourceData *)entity)->PropertiesData), propertyName, standAlone);
  return false;
}

bool EntityManager_GetProperty(const EntityManager *entityManager, const char *entityName, const char *propertyName, void **data) {
  void *entity = NULL;
  ItemsHolder *propertyData;

  if (entityManager == NULL || propertyName == NULL || entityName == NULL) {
    if (Entity_TestMode == false) {
      snprintf(errStr, sizeof(errStr), "Internal error in EntityManager_GetProperty: entityManager (isNull? %d), "
                                       "property name '%s' and entityName '%s' must not be NULL\n",
               entityManager == NULL, propertyName, entityName);
      Utils_Abort(errStr);
    } else
      return false;
  }
  if (EntityManager_IsEntityInUsersList(entityManager, entityName) == true) {
    if (getUser(entityManager, entityName, &entity) == false) {
      snprintf(errStr, sizeof(errStr), "EntityManager_GetProperty: property for user '%s' was not found", entityName);
      return false;
    }
    propertyData = ((userData *)entity)->PropertiesData;
  } else if (EntityManager_IsEntityInGroupsList(entityManager, entityName) == true) {
    if (getGroup(entityManager, entityName, &entity) == true)
      propertyData = ((groupData *)entity)->PropertiesData;
    else {
      snprintf(errStr, sizeof(errStr), "EntityManager_GetProperty: property for group '%s' was not found", entityName);
      return false;
    }
  } else if (EntityManager_IsEntityInResourcesList(entityManager, entityName) == true) {
    if (getResource(entityManager, entityName, &entity) == false) {
      snprintf(errStr, sizeof(errStr), "EntityManager_GetProperty: property for resource '%s' was not found", entityName);
      return false;
    }
    propertyData = ((resourceData *)entity)->PropertiesData;
  } else {
    snprintf(errStr, sizeof(errStr), "EntityManager_GetProperty: entityName is not in entity list");
    return false;
  }
  return getProperty(propertyData, propertyName, data);
}
