#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "hashtab/standard.h"
#include "hashtab/hashtab.h"

#include "libsecurity/acl/aclEntry.h"

#define ACL_DEBUG 0
#define debug_print(fmt, ...)                                                                                                              \
  {                                                                                                                                        \
    if (ACL_DEBUG) DEBUG(fmt, __VA_ARGS__);                                                                                                \
  }

#define MIN_PERMISSION_NAME_LEN 1
#define MAX_PERMISSION_NAME_LEN 50

#define MAX_STORE_LOAD_LEN 50

extern bool AclEntry_TestMode;

#define PERMISSION_VAL "set"

#define PERMISSION_PREFIX "p-"

#define ACL_ENTRY_PREFIX "ac-"
#define ACL_ENTRY_PREFIX_FMT "%s%s"

#define ACL_ENTRY_NAME_FMT "%s"
#define NAME_PREFIX_FMT "%s%s"
#define ACL_ENTRY_KEY_FMT "%s%s%d"

bool addPermissionToEntry(AclPermissionsS *aclEntry, const char *key);
bool checkPermissionValidity(const char *permission);
bool removePermissionFromEntry(const AclPermissionsS *aclEntry, const char *key);
bool checkPermissionOfEntry(const AclPermissionsS *aclEntry, const char *permission);
bool updateEntryPermissions(const AclPermissionsS *srcEntry, AclPermissionsS **destEntry);
