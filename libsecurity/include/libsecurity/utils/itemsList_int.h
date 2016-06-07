#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/utils/itemsList.h"

#include "hashtab/standard.h"
#include "hashtab/hashtab.h"

#define ITEMS_LIST_DEBUG 0

#define MAX_NUMBER_OF_ITEMS 50
#define MAX_FILE_NAME 50

#define ITEM_LIST_PREFIX "IL"
#define ITEM_LIST_FMT "%s%d"

STATIC void clearItemList(void (*removeItem)(void *item), ItemsHolder **items);
STATIC bool containItemsList(bool (*itemEqual)(const void *item1, const void *item2), const ItemsHolder *items1, const ItemsHolder *items2);
