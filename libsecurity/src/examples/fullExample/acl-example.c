#include "example.h"

const char *resourcesList[EXP_NUM_OF_RESOURCES] = {"disk", "file", "camera", "router"};
const char *permissionsList[EXP_NUM_OF_PERMISSIONS] = {"can use", "read", "can take"};
const char *groupPermission = "The group can use it";
const char *allPermission = "all can read";

static bool createResources(EntityManager *entityManager) {
  int16_t i=0;

  for (i=0 ; i<EXP_NUM_OF_RESOURCES ; i++) {
    if (EntityManager_AddResource(entityManager, resourcesList[i]) == false) {
      printf("Error: Can't add resource '%s' to the entity manager, error: %s\n", resourcesList[i], errStr);
      return false;
    }
  }
  EntityManager_PrintFull(stdout, "Entity manager after adding resources:\n", entityManager);
  return true;
}

static bool addPermissionsToResource(EntityManager *entityManager) {
  int16_t i=0;
  char userName[EXP_MAX_USER_NAME];
  const char *resourceName=NULL, *permissionName=NULL;

  for (i=0 ; i<EXP_NUM_OF_USERS ; i++) {
    if (i == EXP_REMOVED_USER_IDX)
      continue;
    snprintf(userName, sizeof(userName), USER_NAME_FMT, i);
    resourceName = resourcesList[i%EXP_NUM_OF_RESOURCES];
    permissionName = permissionsList[i%EXP_NUM_OF_PERMISSIONS];
    if (Acl_AddPermissionToResource(entityManager, resourceName, userName, permissionName) == false) {
      printf("Error when attempting to add permission '%s' to user '%s', error: %s\n", permissionName, userName, errStr);      
      return false;
    }
    if ((i%2)==1) {
      // set the permission for the resource to all the entities
      Acl_AddPermissionToResource(entityManager, resourceName, ALL_ACL_NAME, allPermission);
    }
  }
  resourceName = resourcesList[0];
  // set the permission to the resource to all users of the group
  if (Acl_AddPermissionToResource(entityManager, resourceName, GROUP_NAME_FMT, groupPermission) == false) {
    printf("Error when attempting to add permission '%s' to user '%s', error: %s\n", groupPermission, GROUP_NAME_FMT, errStr);
    return false;
  }
  EntityManager_PrintFull(stdout, "Entity manager after adding ACL to resources: ", entityManager);
  snprintf(userName, sizeof(userName), USER_NAME_FMT, EXP_NUM_OF_USERS-1);
  EntityManager_RemoveUser(entityManager, userName);
  printf("Remove user '%s'\n", userName);
  EntityManager_PrintFull(stdout, "Entity manager with ACL: ", entityManager);
  EntityManager_AddUser(entityManager, userName);
  printf("Add user '%s'\n", userName);
  snprintf(userName, sizeof(userName), USER_NAME_FMT, EXP_REMOVED_USER_IDX);
  EntityManager_AddUser(entityManager, userName);
  printf("Add user '%s'\n", userName);
  return true;
}

static bool checkPermissions(EntityManager *entityManager) {
  int16_t res;
  char userName[EXP_MAX_USER_NAME];
  const char *resourceName=NULL, *permission=NULL;
  AclPermissionsS *permissionsVec=NULL;
  htab *whoUses=NULL;
  const char *haveStr[] = {"doesn't have", "has"};

  snprintf(userName, sizeof(userName), USER_NAME_FMT, 1);
  resourceName = resourcesList[0];
  Acl_NewPermissionsList("", &permissionsVec);
  Acl_GetAllPermissions(entityManager, resourceName, permissionsVec);
  printf("The permissions for resource '%s' are:\n", resourceName);
  Acl_PrintPermissionsList(stdout, "", permissionsVec);
  Acl_FreePermissionsList(permissionsVec);
  resourceName = resourcesList[1];
  Acl_NewPermissionsList("", &permissionsVec);
  Acl_GetUserPermissions(entityManager, resourceName, userName, &permissionsVec);
  printf("User '%s' has for resource '%s' ", userName, resourceName);
  Acl_PrintPermissionsList(stdout, "", permissionsVec);
  Acl_FreePermissionsList(permissionsVec);
  permission = permissionsList[0];
  res = Acl_CheckEntityPermission(entityManager, resourceName, userName, permission);
  printf("User '%s' %s permission '%s' for resource '%s'\n", userName, haveStr[res], permission, resourceName);
  permission = permissionsList[1];
  res = Acl_CheckEntityPermission(entityManager, resourceName, userName, permission);
  printf("User '%s' %s permission '%s' for resource '%s'\n", userName, haveStr[res], permission, resourceName);
  whoUses = hcreate(H_TAB_SIZE);
  Acl_WhoUseAPermission(entityManager, allPermission, whoUses);
  printf("Users that have permission '%s':\n", allPermission);
  Utils_PrintHashKeys("", "  -", whoUses);
  hdestroy(whoUses);
  return true;
}

bool AddAcl(EntityManager *entityManager) {
  createResources(entityManager);
  addPermissionsToResource(entityManager);
  return checkPermissions(entityManager);
}
