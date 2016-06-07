/* old use
#ifndef _TEST_ACL_H_
#define _TEST_ACL_H_

#include "libsecurity/acl/acl_int.h"

#define ACL_ENTRY_NAME "try-entry"
#define BOTH_ENTRY_NAME	"both"
#define ALL_PERMISSION	"All can user it"
#define ENTRY_PERMISSION "p1"
#define BOTH_PERMISSION "both"

const char *AclName = "Test-Acl";
const char *AclResourceName = "Camera-1";

int testAddPermission();
int testAddRemovePermission();
int testCheckPermission();

#endif
*/