#include "libsecurity/entity/entity_int.h"

bool Entity_TestMode = false;
ItemsHolder *callModulesList = NULL;
const char *HandledModuleNameList[NUM_OF_LOAD_STORE_PROPERTIES] = { OTP_PROPERTY_NAME, AM_PROPERTY_NAME, PWD_PROPERTY_NAME, ACL_PROPERTY_NAME };

void setData(const char *name, char **namePtr, ItemsHolder **propertiesData) {
  char *nameStr = NULL;

  if (name == NULL) {
    assert(LIB_NAME "Name string must not be NULL" && (false || Entity_TestMode));
  }
  Utils_CreateAndCopyString(&nameStr, name, strlen(name));
  *namePtr = nameStr;
  ItemsList_New(propertiesData);
  if (callModulesList == NULL) {
    ItemsList_New(&callModulesList);
  }
}

bool newUser(userData **entity, const char *name) {
  if (name == NULL) {
    assert(LIB_NAME "Name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (Utils_CheckNameValidity("newUser", name, MIN_ENTITY_NAME_LEN, MAX_ENTITY_NAME_LEN) == false) return false;
  Utils_Malloc((void **)entity, sizeof(userData));
  setData(name, &((*entity)->Name), &((*entity)->PropertiesData));
  return true;
}

bool newGroup(groupData **entity, const char *name) {
  if (name == NULL) {
    assert(LIB_NAME "Name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (Utils_CheckNameValidity("newGroup", name, MIN_ENTITY_NAME_LEN, MAX_ENTITY_NAME_LEN) == false) return false;
  Utils_Malloc((void **)entity, sizeof(groupData));
  (*entity)->Members = hcreate(H_TAB_SIZE);
  setData(name, &((*entity)->Name), &((*entity)->PropertiesData));
  return true;
}

bool newResource(resourceData **entity, const char *name) {
  if (name == NULL) {
    assert(LIB_NAME "Name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (Utils_CheckNameValidity("newResource", name, MIN_ENTITY_NAME_LEN, MAX_ENTITY_NAME_LEN) == false) return false;
  Utils_Malloc((void **)entity, sizeof(resourceData));
  setData(name, &((*entity)->Name), &((*entity)->PropertiesData));
  return true;
}

// item is used to save the prototype
void removeNone(void *item) {
  if (item == NULL) return;
  return;
}

// Must be used in a loop
bool removeUserFromGroup(htab *t, const char *name) {
  if (t == NULL || name == NULL) {
    assert(LIB_NAME "Hash tab structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (hfind(t, (const ub1 *)name, (ub4)strlen(name)) == true) {
    Utils_Free(hkey(t));
    return true;
  }
  return false;
}

// can't be used from a loop
bool removeAUserFromGroup(const groupData *entity, const char *name) {
  htab *t = NULL;

  if (entity == NULL || name == NULL) {
    assert(LIB_NAME "group data structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  t = entity->Members;
  if (hfind(t, (const ub1 *)name, (ub4)strlen(name)) == true) {
    Utils_Free(hkey(t));
    hdel(t);
    return true;
  }
  return false;
}

// note: for application free root entity and ACL all shell not be done
// Importent: The call must be from the EntitysList_ functions: so the remove item from all registered functions will be done
void freeUser(void *u) {
  if (u == NULL) return;
  Utils_Free(((userData *)u)->Name);
  freePropertyList(((userData *)u)->PropertiesData);
  Utils_Free(u);
}

void freeGroup(void *u) {
  groupData *entity = NULL;
  htab *t = NULL;

  if (u == NULL) return;
  entity = (groupData *)u;
  Utils_Free(entity->Name);
  freePropertyList(entity->PropertiesData);
  t = entity->Members;
  if (hfirst(t)) {
    do {
      removeUserFromGroup(t, (char *)hkey(t));
    } while (hnext(t));
    hdel(t);
  }
  hdestroy(entity->Members);
  Utils_Free(entity);
}

void freeResource(void *u) {
  if (u == NULL) return;
  Utils_Free(((resourceData *)u)->Name);
  freePropertyList(((resourceData *)u)->PropertiesData);
  Utils_Free(u);
}

bool addUserToGroup(const groupData *entity, const char *name) {
  char *nameStr = NULL;

  if (entity == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "Error: addUserToGroup: entityData and member name must not be NULL");
    assert(LIB_NAME "Group data structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (hfind(entity->Members, (const ub1 *)name, (ub4)strlen(name)) == true) {
    return false;
  }
  if (hadd(entity->Members, (const ub1 *)name, (ub4)strlen(name), "ENTITY")) {
    Utils_CreateAndCopyString(&nameStr, name, strlen(name));
    hkey(entity->Members) = (unsigned char *)nameStr;
  } else {
    printf("Internal error: Member: %s is already in members list of '%s'\n", name, entity->Name);
    return false;
  }
  return true;
}

bool isUserPartOfGroup(const groupData *entity, const char *name) {
  if (entity == NULL || name == NULL) {
    assert(LIB_NAME "Group data structure and name string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  return hfind(entity->Members, (const ub1 *)name, (ub4)strlen(name));
}

typedef void (*PrintFunc)(FILE *ofp, const char *header, const void *p);

void printProperties(FILE *ofp, const ItemsHolder *propertiesData) {
  int16_t i = 0;
  char funcName[MAX_FUNC_NAME + 1];
  void *val = NULL, *fData = NULL;
  void (*printFunc)(FILE *ofp, const char *header, const void *p);

  for (i = 0; i < NUM_OF_LOAD_STORE_PROPERTIES; i++) {
    if (getProperty(propertiesData, HandledModuleNameList[i], &val) == true) {
      getCallName(HandledModuleNameList[i], PRINT_FUNC_IDX, funcName, MAX_FUNC_NAME);
      if (ItemsList_GetItem(callModulesList, funcName, &fData) == true) {
        printFunc = (void (*)(FILE *ofp, const char *header, const void *p))fData;
        printFunc(ofp, "", val);
      }
    }
  }
}

bool storeProperties(const ItemsHolder *propertiesData, const SecureStorageS *storage, const char *prefix) {
  int16_t i = 0;
  char funcName[MAX_FUNC_NAME + 1];
  void *val = NULL, *fData = NULL;
  int16_t (*storeFunc)(const void *entity, const SecureStorageS *storage, const char *prefix);

  if (Utils_IsPrefixValid("storeProperties", prefix) == false) return false;
  for (i = 0; i < NUM_OF_LOAD_STORE_PROPERTIES; i++) {
    if (getProperty(propertiesData, HandledModuleNameList[i], &val) == true) {
      getCallName(HandledModuleNameList[i], STORE_FUNC_IDX, funcName, MAX_FUNC_NAME);
      if (ItemsList_GetItem(callModulesList, funcName, &fData) == true) {
        storeFunc = (int16_t (*)(const void *entity, const SecureStorageS *storage, const char *prefix))fData;
        if (storeFunc(val, storage, prefix) == false) return false;
      }
    }
  }
  return true;
}

bool loadProperties(ItemsHolder **propertiesData, const SecureStorageS *storage, const char *prefix) {
  int16_t i = 0;
  char funcName[MAX_FUNC_NAME + 1];
  char *tName = NULL;
  void *val = NULL, *fData = NULL;
  int16_t (*loadFunc)(void **entity, const SecureStorageS *storage, const char *prefix, char **retName);

  if (Utils_IsPrefixValid("loadProperties", prefix) == false) return false;
  for (i = 0; i < NUM_OF_LOAD_STORE_PROPERTIES; i++) {
    getCallName(HandledModuleNameList[i], LOAD_FUNC_IDX, funcName, MAX_FUNC_NAME);
    if (ItemsList_GetItem(callModulesList, funcName, &fData) == true) {
      loadFunc = (int16_t (*)(void **entity, const SecureStorageS *storage, const char *prefix, char **retName))fData;
      if (loadFunc(&val, storage, prefix, &tName) == true) {
        if (registerProperty(*propertiesData, HandledModuleNameList[i], val) == false) {
          fprintf(stdout, "entityData: loadProperties, Internal error: can't "
                          "add property to "
                          "module '%s', error: %s\n",
                  HandledModuleNameList[i], errStr);
        }
      }
    }
  }
  return true;
}

void generateMembersPrefix(const char *prefix, char **key) {
  int16_t prefixLen = strlen(prefix) + strlen(MEMBERS_PREFIX) + 1;
  Utils_Malloc((void **)(key), prefixLen);
  snprintf(*key, prefixLen, MEMBERS_PREFIX_FMT, prefix, MEMBERS_PREFIX);
}

bool storeMembers(const groupData *entity, const SecureStorageS *storage, const char *prefix) {
  int16_t cnt = 1;
  char data[MAX_ENTITY_NAME_LEN];
  char *key = NULL;
  htab *t;

  if (entity == NULL || storage == NULL || prefix == NULL) {
    assert(LIB_NAME "Group data and storage structures as well as prefix must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (Utils_IsPrefixValid("storeMembers", prefix) == false) return false;
  t = entity->Members;
  generateMembersPrefix(prefix, &key);
  snprintf(data, MAX_PREFIX_LEN, "%d", (int16_t)hcount(t));
  if (SecureStorage_AddItem(storage, (const unsigned char *)key, strlen(key), (unsigned char *)data, strlen(data)) == false) {
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", key, data);
    return false;
  }
  debug_print("Add to storage: key: '%s' val '%s'\n", key, data);
  if (hfirst(t)) {
    do {
      snprintf(data, sizeof(data), MEMBER_LIST_FMT, key, MEMBER_NAME_PREFIX, cnt++);
      if (SecureStorage_AddItem(storage, (unsigned char *)data, strlen(data), (unsigned char *)hkey(t), strlen((char *)hkey(t))) == false) {
        snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", data, (char *)hkey(t));
        Utils_Free((void *)key);
        return false;
      }
      debug_print("Add to storage: key: '%s' val '%s'\n", data, (char *)hkey(t));
    } while (hnext(t));
  }
  Utils_Free((void *)key);
  return true;
}

bool loadMembers(groupData **entity, const SecureStorageS *storage, const char *prefix) {
  int16_t i = 0, len = 0;
  bool ret = false;
  char *val = NULL, *key = NULL;
  char mKey[MAX_PREFIX_LEN + 1];

  if (storage == NULL) {
    snprintf(errStr, sizeof(errStr), "Storage must initiated first");
    assert(LIB_NAME "Storage structure must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (Utils_IsPrefixValid("loadMembers", prefix) == false) return false;
  generateMembersPrefix(prefix, &key);
  if (SecureStorage_GetItem(storage, (const unsigned char *)key, strlen(key), (unsigned char **)&val) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: loadMembers, Read from "
                                     "secure storage key '%s' not found",
             key);
    Utils_Free((void *)key);
    return false;
  }
  len = atoi(val);
  if (len > MAX_NUMBER_OF_MEMBERS) {
    fprintf(stderr, "Internal error: number of members was %d, set to the maximum %d\n", len, MAX_NUMBER_OF_MEMBERS);
  }
  if (len > MAX_NUMBER_OF_MEMBERS) len = MAX_NUMBER_OF_MEMBERS;
  debug_print("Read from storage: key: '%s' val '%s' (num of entity %d)\n", key, val, len);
  Utils_Free(val);
  for (i = 0; i < len; i++) {
    snprintf(mKey, sizeof(mKey), MEMBER_LIST_FMT, key, MEMBER_NAME_PREFIX, i + 1);
    if (SecureStorage_GetItem(storage, (unsigned char *)mKey, strlen(mKey), (unsigned char **)&val) == false) {
      snprintf(errStr, sizeof(errStr), "Internal Error: loadMembers, Read from "
                                       "secure storage key '%s' not found",
               mKey);
      Utils_Free((void *)key);
      return false;
    }
    debug_print("Read from storage: key: '%s' user name '%s'\n", mKey, val);
    ret = addUserToGroup(*entity, (char *)val);
    Utils_Free(val);
    if (ret == false) {
      char *name = NULL;
      if (*entity != NULL) name = (*entity)->Name;
      printf("Internal error when reading from secure storage: can't add "
             "entity member '%s' to entity '%s', error: %s\n",
             val, name, errStr);
      Utils_Free((void *)key);
      return false;
    }
  }
  Utils_Free((void *)key);
  return true;
}

bool store(const void *entity, const SecureStorageS *storage, const char *modulePrefix, bool groupFlag, const char *name, ItemsHolder *propertyData) {
  bool ret = true;
  char *prefix = NULL;

  if (entity == NULL || storage == NULL) {
    assert(LIB_NAME "Storage and entity structures must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  if (Utils_IsPrefixValid("Store", modulePrefix) == false) return false;
  if (EntityManager_StoreName(storage, modulePrefix, name, &prefix) == false) return false;
  if (groupFlag) ret = storeMembers((const groupData *)entity, storage, prefix);
  ret = ret && storeProperties(propertyData, storage, prefix);
  Utils_Free((void *)prefix);
  return ret;
}

bool storeUsers(const void *entity, const SecureStorageS *storage, const char *prefix) {
  if (entity == NULL || storage == NULL || prefix == NULL) {
    assert(LIB_NAME "Entity and storage structures as well as prefix string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  return store(entity, storage, prefix, false, ((const userData *)entity)->Name, ((const userData *)entity)->PropertiesData);
}

bool storeGroups(const void *entity, const SecureStorageS *storage, const char *prefix) {
  if (entity == NULL || storage == NULL || prefix == NULL) {
    assert(LIB_NAME "Entity and storage structures as well as prefix string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  return store(entity, storage, prefix, true, ((const groupData *)entity)->Name, ((const groupData *)entity)->PropertiesData);
}

bool storeResources(const void *entity, const SecureStorageS *storage, const char *prefix) {
  if (entity == NULL || storage == NULL || prefix == NULL) {
    assert(LIB_NAME "Entity and storage structures as well as prefix string must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  return store(entity, storage, prefix, false, ((const resourceData *)entity)->Name, ((const resourceData *)entity)->PropertiesData);
}

bool load(void **entity, const SecureStorageS *storage, const char *modulePrefix, char **retName) {
  bool ret = true;
  char *val = NULL, *prefix = NULL;
  ItemsHolder *propertyData = NULL;

  if (storage == NULL) {
    assert(LIB_NAME "Storage structure must not be NULL" && (false || Entity_TestMode));
    snprintf(errStr, sizeof(errStr), "Storage must initiated first");
    return false;
  }
  if (Utils_IsPrefixValid("Load", modulePrefix) == false) return false;
  if (EntityManager_LoadName(storage, modulePrefix, &val, &prefix) == false) return false;
  if (strncmp(modulePrefix, USER_PREFIX, strlen(USER_PREFIX)) == 0) {
    newUser((userData **)entity, val);
    propertyData = ((userData *)(*entity))->PropertiesData;
  } else if (strncmp(modulePrefix, GROUP_PREFIX, strlen(GROUP_PREFIX)) == 0) {
    newGroup((groupData **)entity, val);
    propertyData = ((groupData *)(*entity))->PropertiesData;
  } else {
    newResource((resourceData **)entity, val);
    propertyData = ((resourceData *)(*entity))->PropertiesData;
  }
  Utils_CreateAndCopyString(retName, val, strlen(val));
  Utils_Free(val);
  if (strncmp(modulePrefix, GROUP_PREFIX, strlen(GROUP_PREFIX)) == 0) {
    ret = loadMembers((groupData **)entity, storage, prefix);
  }
  ret = ret && loadProperties(&propertyData, storage, prefix);
  Utils_Free((void *)prefix);
  return ret;
}

bool isEqualProperties(const ItemsHolder *propertiesData1, const ItemsHolder *propertiesData2) {
  int16_t i = 0;
  char funcName[MAX_FUNC_NAME + 1];
  void *val1 = NULL, *val2 = NULL, *fData = NULL;
  int16_t (*isEqualFunc)(const void *u1, const void *u2);

  if (propertiesData1 == NULL || propertiesData2 == NULL) {
    return false;
  }
  for (i = 0; i < NUM_OF_LOAD_STORE_PROPERTIES; i++) {
    if (getProperty(propertiesData1, HandledModuleNameList[i], &val1) == true) {
      getCallName(HandledModuleNameList[i], IS_EQUAL_FUNC_IDX, funcName, MAX_FUNC_NAME);
      getProperty(propertiesData2, HandledModuleNameList[i], &val2);
      if (ItemsList_GetItem(callModulesList, funcName, &fData) == true) {
        isEqualFunc = (int16_t (*)(const void *u1, const void *u2))fData;
        if (isEqualFunc((void *)val1, (void *)val2) == false) {
          snprintf(errStr, sizeof(errStr), "Is equal for module %s fail", HandledModuleNameList[i]);
          return false;
        }
      }
    }
  }
  return true;
}

bool isContainsMembers(const groupData *entity1, const groupData *entity2) {
  char *name = NULL;
  htab *t1 = NULL;

  if (entity1 == NULL || entity2 == NULL) {
    assert(LIB_NAME "Entity structure must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  t1 = entity1->Members;
  if (hfirst(t1)) {
    do {
      name = (char *)hkey(t1);
      if (isUserPartOfGroup(entity2, name) == false) {
        debug_print("entityData '%s' wasn't found in entity '%s' members\n", name, entity2->Name);
        return false;
      }
    } while (hnext(t1));
  }
  return true;
}

bool isEqualMembers(const groupData *entity1, const groupData *entity2) {
  if (entity1 == NULL || entity2 == NULL) {
    return false;
  }
  return isContainsMembers(entity1, entity2) == true && (hcount(entity1->Members) == hcount(entity2->Members));
}

bool isEqualUsers(const void *u1, const void *u2) {
  const userData *entity1 = NULL, *entity2 = NULL;

  if (u1 == NULL || u2 == NULL) {
    assert(LIB_NAME "User data structure must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  entity1 = (const userData *)u1;
  entity2 = (const userData *)u2;
  if (strcmp(entity1->Name, entity2->Name) != 0) return false;
  return isEqualProperties(entity1->PropertiesData, entity2->PropertiesData);
}

bool isEqualGroups(const void *u1, const void *u2) {
  const groupData *entity1 = NULL, *entity2 = NULL;

  if (u1 == NULL || u2 == NULL) {
    assert(LIB_NAME "Group data structure must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  entity1 = (const groupData *)u1;
  entity2 = (const groupData *)u2;
  if (strcmp(entity1->Name, entity2->Name) != 0) return false;
  if (isEqualMembers(entity1, entity2) == false) {
    return false;
  }
  return isEqualProperties(entity1->PropertiesData, entity2->PropertiesData);
}

bool isEqualResources(const void *u1, const void *u2) {
  const resourceData *entity1 = NULL, *entity2 = NULL;

  if (u1 == NULL || u2 == NULL) {
    assert(LIB_NAME "Resource data structure must not be NULL" && (false || Entity_TestMode));
    return false;
  }
  entity1 = (const resourceData *)u1;
  entity2 = (const resourceData *)u2;
  if (strcmp(entity1->Name, entity2->Name) != 0) return false;
  return isEqualProperties(entity1->PropertiesData, entity2->PropertiesData);
}

void getCallName(const char *propertyName, int16_t funcIdx, char *callStr, int16_t maxLen) {
  if (funcIdx < 0 || funcIdx >= NUM_OF_ITEMS_FUNC) {
    snprintf(errStr, sizeof(errStr), "Internal error in: getCallName, func Idx = %d, not in the range 0-%d", funcIdx, NUM_OF_ITEMS_FUNC);
    Utils_Abort(errStr);
  }
  snprintf(callStr, maxLen, "%s-%d", propertyName, funcIdx);
}

bool registerPropertyHandleFunc(const char *propertyName, void (*removeItem)(void *item),
                                bool (*storeItem)(const void *u, const SecureStorageS *storage, const char *prefix),
                                bool (*loadItem)(void **u, const SecureStorageS *storage, const char *prefix, char **retName),
                                void (*printItem)(FILE *ofp, const char *header, const void *p),
                                bool (*isEqual)(const void *entity1, const void *entity2)) {
  char funcName[MAX_FUNC_NAME + 1];
  bool ret = false;

  if (propertyName == NULL) {
    if (Entity_TestMode == false) {
      snprintf(errStr, sizeof(errStr), "Internal error in RegisterRemoveProperty: module name '%s' must not be NULL\n", propertyName);
      Utils_Abort(errStr);
    } else
      return false;
  }
  debug_print("Add remove func property of module '%s'\n", propertyName);
  if (callModulesList == NULL) ItemsList_New(&callModulesList);
  getCallName(propertyName, REMOVE_FUNC_IDX, funcName, MAX_FUNC_NAME);
  ret = ItemsList_AddItem(callModulesList, funcName, (void *)removeItem);
  getCallName(propertyName, STORE_FUNC_IDX, funcName, MAX_FUNC_NAME);
  ret = ret && ItemsList_AddItem(callModulesList, funcName, (void *)storeItem);
  getCallName(propertyName, LOAD_FUNC_IDX, funcName, MAX_FUNC_NAME);
  ret = ret && ItemsList_AddItem(callModulesList, funcName, (void *)loadItem);
  getCallName(propertyName, PRINT_FUNC_IDX, funcName, MAX_FUNC_NAME);
  ret = ret && ItemsList_AddItem(callModulesList, funcName, (void *)printItem);
  getCallName(propertyName, IS_EQUAL_FUNC_IDX, funcName, MAX_FUNC_NAME);
  ret = ret && ItemsList_AddItem(callModulesList, funcName, (void *)isEqual);
  return ret;
}

void removeRegisteredPropertyList() {
  ItemsList_FreeAllItems(removeNone, callModulesList);
  callModulesList = NULL;
}

bool registerProperty(const ItemsHolder *propertiesData, const char *propertyName, void *itemData) {
  if (propertyName == NULL || itemData == NULL || propertiesData == NULL) {
    if (Entity_TestMode == false) {
      snprintf(errStr, sizeof(errStr), "Internal error in EntitysList_RegisterPropertyStruct: "
                                       "property name '%s' "
                                       "entity and data must not be NULL\n",
               propertyName);
      Utils_Abort(errStr);
    } else
      return false;
  }
  debug_print("Add property '%s'\n", propertyName);
  return ItemsList_AddItem(propertiesData, propertyName, itemData);
}

bool removeProperty(ItemsHolder *propertiesData, const char *propertyName, bool standAlone) {
  void *data = NULL, *fData = NULL;
  void (*removeFunc)(void *);
  char funcName[MAX_FUNC_NAME + 1];

  if (propertyName == NULL || propertiesData == NULL) {
    if (Entity_TestMode == false) {
      snprintf(errStr, sizeof(errStr), "Internal error in removeProperty: property name '%s' "
                                       "and entity must not be NULL\n",
               (const char *)propertyName);
      Utils_Abort(errStr);
    } else
      return false;
  }

  if (getProperty(propertiesData, propertyName, &data) == true) {
    getCallName(propertyName, REMOVE_FUNC_IDX, funcName, MAX_FUNC_NAME);
    if (ItemsList_GetItem(callModulesList, funcName, &fData) == true) {
      removeFunc = (void (*)(void *))fData;
      removeFunc(data);
      if (standAlone) // in loop the entry can't be removed
        ItemsList_ClearItem(removeNone, propertiesData, propertyName);
    } else {
      return false;
    }
    return true;
  }
  return false;
}

bool getProperty(const ItemsHolder *propertiesData, const char *name, void **data) {
  if (name == NULL || propertiesData == NULL) {
    if (Entity_TestMode == false)
      fprintf(stderr, "Error in getProperty: name '%s' and property data (isNull %d) must not be NULL\n", name, propertiesData == NULL);
    return false;
  }
  return ItemsList_GetItem(propertiesData, name, data);
}

void freePropertyList(ItemsHolder *propertyData) {
  char *name = NULL;
  htab *t = NULL;

  if (propertyData == NULL) return;
  t = propertyData->Items;
  if (hfirst(t)) {
    do {
      name = (char *)hkey(t);
      removeProperty(propertyData, name, false);
    } while (hnext(t));
  }
  ItemsList_FreeAllItems(removeNone, propertyData);
}
