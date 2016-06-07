#pragma once

#include "libsecurity/storage/secureStorage.h"
#include "libsecurity/utils/itemsList.h"
#include "libsecurity/entity/entityManager.h"
#include "libsecurity/libsecurity/libsecurity_params.h"

#define MIN_ENTITY_NAME_LEN 1
#define MAX_ENTITY_NAME_LEN 140

typedef struct {
  char *Name;
  ItemsHolder *PropertiesData;
} userData;

typedef struct {
  char *Name;
  htab *Members;
  ItemsHolder *PropertiesData;
} groupData;

typedef struct {
  char *Name;
  ItemsHolder *PropertiesData;
} resourceData;

#define NUM_OF_LOAD_STORE_PROPERTIES 4
extern const char *HandledModuleNameList[NUM_OF_LOAD_STORE_PROPERTIES];

extern bool Entity_TestMode;
