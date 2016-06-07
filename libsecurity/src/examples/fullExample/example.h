#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/entity/entityManager.h"
#include "libsecurity/salt/salt.h"
#include "libsecurity/password/password.h"
#include "libsecurity/otp/otpUser.h"
#include "libsecurity/accounts/accounts.h"
#include "libsecurity/acl/acl.h"
#include "libsecurity/acl/aclEntry.h"

#define EXP_MAX_USER_NAME     20
#define EXP_NUM_OF_USERS      5
#define EXP_NUM_OF_RESOURCES  4
#define EXP_NUM_OF_PERMISSIONS 3

#define EXP_REMOVED_USER_IDX  (EXP_NUM_OF_USERS - 3)

#define GROUP_NAME_FMT "group1"
#define USER_NAME_FMT "User %d"

bool AddUsersGroups(EntityManager *entityManager);
bool AddAcl(EntityManager *entityManager);
bool AddOtp(EntityManager *entityManager, int16_t userId);
bool AddPwd(EntityManager *entityManager, int16_t userId);
bool StoreData(EntityManager *entityManager);
