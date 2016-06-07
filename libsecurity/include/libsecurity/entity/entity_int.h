#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/utils/utils.h"
#include "libsecurity/entity/entity.h"

#define MAX_NUMBER_OF_MEMBERS 20

#define ENTITY_STORE_FMT "%s"
#define ENTITY_PREFIX "U"

#define ENTITY_NAME_FMT "%s%s"
#define ENTITY_NAME_POSTFIX "'a9"

#define USER_PREFIX "Us-"
#define GROUP_PREFIX "Gr-"
#define RESOURCE_PREFIX "Rs-"

#define MEMBERS_PREFIX_FMT "%s-%s"
#define MEMBERS_PREFIX "m"
#define MEMBER_LIST_FMT "%s%s%d"
#define MEMBER_NAME_PREFIX "M"

#define MAX_FUNC_NAME 20

#define REMOVE_FUNC_IDX 0
#define STORE_FUNC_IDX 1
#define LOAD_FUNC_IDX 2
#define PRINT_FUNC_IDX 3
#define IS_EQUAL_FUNC_IDX 4
#define NUM_OF_ITEMS_FUNC 5

#define EN_DEBUG 0
#define debug_print(fmt, ...)                                                                                                              \
  {                                                                                                                                        \
    if (EN_DEBUG) DEBUG(fmt, __VA_ARGS__);                                                                                                 \
  }

extern bool AclEntry_TestMode;

bool newUser(userData **entity, const char *name);
bool newGroup(groupData **entity, const char *name);
bool newResource(resourceData **entity, const char *name);
void freeUser(void *entity);
void freeGroup(void *entity);
void freeResource(void *entity);
void setData(const char *name, char **namePtr, ItemsHolder **propertiesData);
bool addUserToGroup(const groupData *entity, const char *name);
bool isUserPartOfGroup(const groupData *entity, const char *name);
bool removeAUserFromGroup(const groupData *entity, const char *name);
bool store(const void *entity, const SecureStorageS *storage, const char *prefix, bool groupFlag, const char *name, ItemsHolder *propertyData);
bool storeUsers(const void *entity, const SecureStorageS *storage, const char *prefix);
bool storeGroups(const void *entity, const SecureStorageS *storage, const char *prefix);
bool storeResources(const void *entity, const SecureStorageS *storage, const char *prefix);
bool load(void **entity, const SecureStorageS *storage, const char *prefix, char **retName);
bool isEqualUsers(const void *entity1, const void *entity2);
bool isEqualGroups(const void *entity1, const void *entity2);
bool isEqualResources(const void *entity1, const void *entity2);

void getCallName(const char *propertyName, int16_t funcIdx, char *callStr, int16_t maxLen);
void printProperties(FILE *ofp, const ItemsHolder *propertiesData);
void removeNone(void *item);
bool removeUserFromGroup(htab *t, const char *name);
void generateMembersPrefix(const char *prefix, char **key);
bool storeMembers(const groupData *entity, const SecureStorageS *storage, const char *prefix);
bool storeProperties(const ItemsHolder *propertiesData, const SecureStorageS *storage, const char *prefix);
bool loadMembers(groupData **entity, const SecureStorageS *storage, const char *prefix);
bool loadProperties(ItemsHolder **propertiesData, const SecureStorageS *storage, const char *prefix);
bool isEqualProperties(const ItemsHolder *propertiesData1, const ItemsHolder *propertiesData2);
bool isContainsMembers(const groupData *entity1, const groupData *entity2);
bool isEqualMembers(const groupData *entity1, const groupData *entity2);

bool registerProperty(const ItemsHolder *propertiesData, const char *propertyName, void *itemData);
bool registerPropertyHandleFunc(const char *propertyName, void (*removeItem)(void *item),
                                bool (*storeItem)(const void *u, const SecureStorageS *storage, const char *prefix),
                                bool (*loadItem)(void **u, const SecureStorageS *storage, const char *prefix, char **retName),
                                void (*printItem)(FILE *ofp, const char *header, const void *p),
                                bool (*isEqual)(const void *entity1, const void *entity2));
void removeRegisteredPropertyList(void);
bool removeProperty(ItemsHolder *propertiesData, const char *propertyName, bool standAlone);
bool getProperty(const ItemsHolder *propertiesData, const char *propertyName, void **data);

void freePropertyList(ItemsHolder *propertiesData);
