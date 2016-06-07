#pragma once

#include "libsecurity/entity/entity.h"
#include "libsecurity/utils/itemsList.h"
#include "libsecurity/acl/aclEntry.h"

typedef struct { htab *Entries; } AclS;

typedef struct {
  char *Name;
  htab *Permissions;
} AclPermissionsS;

void Acl_Print(FILE *ofp, const char *prefix, const void *a);
void Acl_PrintPermissionsList(FILE *ofp, const char *prefix, const void *a);
bool Acl_New(AclS **acl);
bool Acl_NewPermissionsList(const char *name, AclPermissionsS **aclEntry);
void Acl_Free(void *a);
void Acl_FreePermissionsList(void *e);
bool Acl_RemoveEntry(void *acl, const char *entryName);
bool Acl_AddPermissionToResource(const EntityManager *entityManager, const char *resourceName, const char *entityName, const char *permission);
bool Acl_RemovePermissionFromResource(const EntityManager *entityManager, const char *resourceName, const char *entityName, const char *permission);
bool Acl_GetAllPermissions(const EntityManager *entityManager, const char *resourceName, AclPermissionsS *pEntry);
bool Acl_GetUserPermissions(const EntityManager *entityManager, const char *resourceName, const char *userName, AclPermissionsS **pEntry);
bool Acl_CheckEntityPermission(const EntityManager *entityManager, const char *resourceName, const char *userName, const char *permission);
bool Acl_WhoUseAPermission(const EntityManager *entityManager, const char *permission, htab *names);

bool Acl_Store(const void *u, const SecureStorageS *storage, const char *prefix);
bool Acl_Load(void **u, const SecureStorageS *storage, const char *prefix, char **retName);
bool Acl_IsEqual(const void *entity1, const void *entity2);
