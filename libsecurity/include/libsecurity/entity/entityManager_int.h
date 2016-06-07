#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "hashtab/standard.h"
#include "hashtab/hashtab.h"

#include "libsecurity/entity/entity_int.h"
#include "libsecurity/entity/entityManager.h"

STATIC void printUser(FILE *ofp, const char *header, const void *entity);
STATIC void printGroup(FILE *ofp, const char *header, const void *entity);
STATIC void printResource(FILE *ofp, const char *header, const void *entity);
STATIC void fullPrintUser(FILE *ofp, const char *header, const void *entity);
STATIC void fullPrintGroup(FILE *ofp, const char *header, const void *entity);
STATIC void fullPrintResource(FILE *ofp, const char *header, const void *entity);

STATIC bool getGroup(const EntityManager *entityManager, const char *name, void **item);
STATIC bool getUser(const EntityManager *entityManager, const char *name, void **item);
STATIC bool getResource(const EntityManager *entityManager, const char *name, void **item);
STATIC bool checkDataAndGetGroup(const EntityManager *entityManager, const char *groupName, const char *userName, groupData **gEntity);
STATIC bool checkAddValidParams(EntityManager *entityManager, const char *name);
STATIC bool getEntity(EntityManager *entityManager, const char *entityName, void **entity);
STATIC bool removeUserFromAllGroups(EntityManager *entityManager, const char *name);
STATIC bool removeUserFromAllResources(EntityManager *entityManager, const char *name);
