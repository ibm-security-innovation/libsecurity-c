#include "libsecurity/acl/aclEntry_int.h"

bool AclEntry_TestMode = false;

// If the permission is valid and was not set yet, add it to the AclPermissionsS's permission list
bool addPermissionToEntry(AclPermissionsS *aclEntry, const char *permission) {
  char *keyStr = NULL;
  htab *t = NULL;

  if (aclEntry == NULL) {
    assert(LIB_NAME "Permission structure must not be NULL" && (false || AclEntry_TestMode));
    return false;
  }
  if (checkPermissionValidity(permission) == false) return false;
  t = aclEntry->Permissions;
  if (hadd(t, (const ub1 *)permission, (ub4)strlen(permission), PERMISSION_VAL) == true) {
    Utils_CreateAndCopyString(&keyStr, permission, strlen(permission));
    hkey(t) = (unsigned char *)keyStr;
  } else {
    return false;
  }
  return true;
}

bool checkPermissionValidity(const char *permission) {
  if (permission == NULL) {
    snprintf(errStr, sizeof(errStr), "Error: permission is not valid, its length must be larger than 0");
    assert(LIB_NAME "Permission structure and permission string must not be NULL" && (false || AclEntry_TestMode));
    return false;
  } else if (strlen(permission) == 0) {
    snprintf(errStr, sizeof(errStr), "Error: permission is not valid, its length is 0");
    return false;
  } else if (strlen(permission) > MAX_PERMISSION_NAME_LEN) {
    snprintf(errStr, sizeof(errStr), "Error: permission is not valid, its length is %d > maximum length %d", (int16_t)strlen(permission),
             MAX_PERMISSION_NAME_LEN);
    return false;
  }
  return true;
}

// if it is not in loop
bool removePermissionFromEntry(const AclPermissionsS *aclEntry, const char *permission) {
  htab *t = NULL;

  if (aclEntry == NULL) {
    assert(LIB_NAME "Permission structure must not be NULL" && (false || AclEntry_TestMode));
    return false;
  }
  if (checkPermissionValidity(permission) == false) return false;
  t = aclEntry->Permissions;
  if (hfirst(t) && hfind(t, (const ub1 *)permission, (ub4)strlen(permission)) == true) {
    Utils_Free(hkey(t));
    hdel(t);
    return true;
  }
  return false;
}

bool updateEntryPermissions(const AclPermissionsS *srcEntry, AclPermissionsS **destEntry) {
  htab *t;

  if (srcEntry == NULL || destEntry == NULL || *destEntry == NULL) {
    snprintf(errStr, sizeof(errStr), "Can't update permissions of NULL aclEntry");
    assert(LIB_NAME "Permission structures must not be NULL" && (false || AclEntry_TestMode));
    return false;
  }
  t = srcEntry->Permissions;
  if (hfirst(t)) {
    do {
      addPermissionToEntry(*destEntry, (char *)hkey(t));
    } while (hnext(t));
  }
  return true;
}

// Check if a given permission is in the AclPermissionsS's list
bool checkPermissionOfEntry(const AclPermissionsS *aclPermissions, const char *permission) {
  if (aclPermissions == NULL) {
    assert(LIB_NAME "Permission structures must not be NULL" && (false || AclEntry_TestMode));
    return false;
  }
  if (checkPermissionValidity(permission) == false) return false;
  return hfind(aclPermissions->Permissions, (const ub1 *)permission, (ub4)strlen(permission));
}
