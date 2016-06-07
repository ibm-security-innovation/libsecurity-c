#pragma once

#include "libsecurity/utils/utils.h"
#include "libsecurity/utils/itemsList.h"

typedef struct {
  ItemsHolder *Users;
  ItemsHolder *Groups;
  ItemsHolder *Resources;
} EntityManager;

void EntityManager_Print(FILE *ofp, const char *header, const EntityManager *entityManager);
void EntityManager_PrintFull(FILE *ofp, const char *header, const EntityManager *entityManager);
void EntityManager_New(EntityManager *entityManager);
bool EntityManager_AddUser(EntityManager *entityManager, const char *name);
bool EntityManager_AddGroup(EntityManager *entityManager, const char *name);
bool EntityManager_AddResource(EntityManager *entityManager, const char *name);
bool EntityManager_RemoveUser(EntityManager *entityManager, const char *name);
bool EntityManager_RemoveGroup(EntityManager *entityManager, const char *name);
bool EntityManager_RemoveResource(EntityManager *entityManager, const char *name);
bool EntityManager_AddUserToGroup(EntityManager *entityManager, const char *groupName, const char *userName);
bool EntityManager_RemoveUserFromGroup(EntityManager *entityManager, const char *groupName, const char *userName);
bool EntityManager_IsUserPartOfAGroup(const EntityManager *entityManager, const char *groupName, const char *userName);

bool EntityManager_StoreName(const SecureStorageS *storage, const char *p1, const char *name, char **prefix);
bool EntityManager_LoadName(const SecureStorageS *storage, const char *p1, char **name, char **prefix);

bool EntityManager_Store(const EntityManager *entityManager, const char *fileName, const unsigned char *secret, const unsigned char *salt);
bool EntityManager_Load(EntityManager **entityManager, const char *fileName, const unsigned char *secret, const unsigned char *salt);

bool EntityManager_IsEqual(const EntityManager *entityManager1, const EntityManager *entityManager2);

bool EntityManager_RegisterProperty(EntityManager *entityManager, const char *name, const char *propertyName, void *itemData);
bool EntityManager_RegisterPropertyHandleFunc(const char *propertyName, void (*removeItem)(void *item),
                                              bool (*storeItem)(const void *u, const SecureStorageS *storage, const char *prefix),
                                              bool (*loadItem)(void **u, const SecureStorageS *storage, const char *prefix, char **retName),
                                              void (*printItem)(FILE *ofp, const char *header, const void *p),
                                              bool (*isEqual)(const void *entity1, const void *entity2));
void EntityManager_RemoveRegisteredPropertyList(void);
bool EntityManager_RemoveProperty(EntityManager *entityManager, const char *name, const char *propertyName, bool standAlone);
bool EntityManager_GetProperty(const EntityManager *entityManager, const char *name, const char *propertyName, void **data);

bool EntityManager_FreeAll(EntityManager *entityManager);
bool EntityManager_Free(EntityManager *entityManager, const char *name);
bool EntityManager_IsEntityInList(const EntityManager *entityManager, const char *name);
bool EntityManager_IsEntityInUsersList(const EntityManager *entityManager, const char *name);
bool EntityManager_IsEntityInGroupsList(const EntityManager *entityManager, const char *name);
bool EntityManager_IsEntityInResourcesList(const EntityManager *entityManager, const char *name);
