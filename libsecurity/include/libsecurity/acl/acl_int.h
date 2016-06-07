#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/acl/aclEntry_int.h"
#include "libsecurity/acl/acl.h"
#include "libsecurity/entity/entityManager.h"

#include "hashtab/standard.h"
#include "hashtab/hashtab.h"

#define ACL_PREFIX "a-"

#define ACL_PREFIX_FMT "%s%s"
#define ACL_KEY_PREFIX "en-"
#define ACL_KEY_FMT "%s%s%d"

#define MAX_NUMBER_OF_USERS_IN_ACL 50

extern bool Acl_TestMode;

STATIC bool addPermissionToResource(AclS *acl, const char *entityName, const char *permission);
STATIC bool addPermissionToResourceHandler(const EntityManager *entityManager, const char *resourceName, const char *entityName, const char *permission);
STATIC bool addEntry(AclS *acl, const char *entityName, AclPermissionsS **aclEntry);
STATIC bool getEntry(const AclS *acl, const char *entryName, AclPermissionsS **entry);
STATIC bool isItAllEntry(const char *name);

STATIC bool storeEntry(const void *a, const SecureStorageS *storage, const char *prefix);
STATIC bool loadEntry(AclS *a, const SecureStorageS *storage, const char *prefix);

STATIC bool isEqualEntry(const void *e1, const void *e2);
