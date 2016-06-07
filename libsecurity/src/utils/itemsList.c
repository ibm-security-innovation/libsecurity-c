#include "libsecurity/utils/itemsList_int.h"

void ItemsList_Print(void (*printItem)(const char *header, const void *item), const char *str, const ItemsHolder *items) {
  htab *t = NULL;

  printf("%s\n", str); // print the header even for NULL items
  if (items == NULL) return;
  t = items->Items;
  if (hfirst(t)) {
    do {
      printItem((void *)hkey(t), (void *)hstuff(t));
    } while (hnext(t));
  }
  printf("\n");
}

void ItemsList_PrintKeys(const char *header, const ItemsHolder *items) {
  htab *t = NULL;

  printf("%s\n", header); // print the header even for NULL items
  if (items == NULL) return;
  t = items->Items;
  if (hfirst(t)) {
    do {
      printf("key: %s\n", (char *)hkey(t));
    } while (hnext(t));
  }
}

void ItemsList_New(ItemsHolder **items) {
  Utils_Malloc((void **)(items), sizeof(ItemsHolder));
  (*items)->Items = hcreate(H_TAB_SIZE);
}

void ItemsList_Duplicate(ItemsHolder *src, ItemsHolder *dest) {
  Utils_DuplicateHash(src->Items, dest->Items);
}

// Note: it can't be used in a loop: the hdel(t) will create an error
bool ItemsList_ClearItem(void (*removeItem)(void *item), ItemsHolder *items, const char *name) {
  htab *t = NULL;

  if (items == NULL || name == NULL) return false;
  t = items->Items;
  if (hfind(t, (const ub1 *)name, (ub4)strlen(name)) == true) {
    removeItem((void *)hstuff(t)); // remove the item name and the item node (the sruff)
    Utils_Free(hkey(t));
    hdel(t);
    return true;
  }
  return false;
}

// Clear all the items from the items list
STATIC void clearItemList(void (*removeItem)(void *item), ItemsHolder **items) {
  htab *t = NULL;

  if (*items == NULL) return;
  t = (*items)->Items;
  if (hfirst(t)) {
    do {
      removeItem((void *)hstuff(t));
      Utils_Free(hkey(t));
    } while (hnext(t));
    hdel(t);
  }
  hdestroy(t);
}

// Clear all the items from the items list
void ItemsList_ClearAllItems(void (*removeItem)(void *item), ItemsHolder **items) {
  if (*items == NULL) return;
  clearItemList(removeItem, items);
  (*items)->Items = hcreate(H_TAB_SIZE);
}

void ItemsList_FreeAllItems(void (*removeItem)(void *item), ItemsHolder *items) {
  if (items == NULL) return;
  clearItemList(removeItem, &items);
  Utils_Free(items);
  items = NULL;
}

bool ItemsList_AddItem(const ItemsHolder *items, const char *name, void *newItem) {
  if (items == NULL) {
    snprintf(errStr, sizeof(errStr), "Items is NULL");
    return false;
  }
  if (newItem == NULL || name == NULL) {
    snprintf(errStr, sizeof(errStr), "New item/Name is NULL");
    return false;
  }
  if (hfind(items->Items, (const ub1 *)name, (ub4)strlen(name)) == true) {
    snprintf(errStr, sizeof(errStr), "Item '%s' was already in list", name);
    return false;
  }
  if (Utils_AddToHash(items->Items, (const unsigned char *)name, strlen(name), (void *)newItem) == false) {
    printf("Internal error: Item: %s is already used\n", name);
    return false;
  }
  return true;
}

bool ItemsList_CheckItem(const ItemsHolder *items, const char *name) {
  if (items == NULL || items->Items == NULL || name == NULL) return false;
  return hfind(items->Items, (const ub1 *)name, (ub4)strlen(name));
}

bool ItemsList_GetItem(const ItemsHolder *items, const char *name, void **item) {
  if (items == NULL || items->Items == NULL || name == NULL) return false;
  return Utils_GetValFromHash(items->Items, (const unsigned char *)name, strlen(name), item);
}

bool ItemsList_AddToStorage(bool (*storeItem)(const void *item, const SecureStorageS *storage, const char *data), const ItemsHolder *items,
                            const SecureStorageS *storage, const char *prefix) {
  int16_t cnt = 1;
  char data[MAX_ITEM_NAME_LEN + 10];
  htab *t = NULL;

  if (items == NULL || storage == NULL) return false;
  t = items->Items;
  sprintf(data, "%d", (int)hcount(t));
  if (SecureStorage_AddItem(storage, (const unsigned char *)prefix, strlen(prefix), (unsigned char *)data, strlen(data)) == false) {
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", prefix, data);
    return false;
  }
  if (ITEMS_LIST_DEBUG) {
    printf("Add to storage: key: '%s' val '%s'\n", prefix, data);
  }
  if (hfirst(t)) {
    do {
      sprintf(data, ITEM_LIST_FMT, prefix, cnt++);
      if (storeItem((void *)hstuff(t), storage, data) == false) return false;
    } while (hnext(t));
  }
  if (ITEMS_LIST_DEBUG) {
    printf("All items were added to the storage\n");
  }
  return true;
}

bool ItemsList_LoadFromStorage(bool (*itemLoad)(void **item, const SecureStorageS *storage, const char *prefix, char **retName),
                               ItemsHolder **items, const SecureStorageS *storage, const char *prefix, void (*itemFree)(void *item)) {
  int16_t i = 0, len = 0;
  char *val = NULL, *name = NULL;
  char key[MAX_PREFIX_LEN];
  void *item = NULL;

  if (*items == NULL || storage == NULL) return false;
  if (SecureStorage_GetItem(storage, (const unsigned char *)prefix, strlen(prefix), (unsigned char **)&val) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: Read from secure storage key '%s' not found", prefix);
    return false;
  }
  len = atoi(val);
  if (len > MAX_NUMBER_OF_ITEMS) {
    fprintf(stderr, "Internal error: number of items was %d, set to the maximum %d\n", len, MAX_NUMBER_OF_ITEMS);
    len = MAX_NUMBER_OF_ITEMS;
  }
  if (ITEMS_LIST_DEBUG) {
    printf("Read from storage: key: '%s' val (num of items) '%s'\n", prefix, val);
  }
  Utils_Free(val);
  for (i = 0; i < len; i++) {
    snprintf(key, sizeof(key), ITEM_LIST_FMT, prefix, i + 1);
    if (itemLoad((void **)(&item), storage, key, &name) == false) return false;
    if (ItemsList_AddItem(*items, name, item) == false) {
      itemFree(item);
    }
    Utils_Free(name);
  }
  return true;
}

STATIC bool containItemsList(bool (*itemEqual)(const void *item1, const void *item2), const ItemsHolder *items1, const ItemsHolder *items2) {
  htab *t1 = NULL;
  void *tItem = NULL;

  if (items1 == NULL || items2 == NULL) {
    return false;
  }
  t1 = items1->Items;
  if (hfirst(t1)) {
    do {
      if (hfind(items2->Items, (const ub1 *)hkey(t1), strlen((char *)hkey(t1))) == true) {
        tItem = (void *)hstuff(items2->Items);
      } else {
        if (ITEMS_LIST_DEBUG) printf("Item '%s' wasn't found on the second items list\n", (char *)hkey(t1));
        return false;
      }
      if (itemEqual((void *)hstuff(t1), tItem) == false) return false;
    } while (hnext(t1));
  }
  return true;
}

bool ItemsList_IsEqual(bool (*itemEqual)(const void *item1, const void *item2), const ItemsHolder *items1, const ItemsHolder *items2) {
  return containItemsList(itemEqual, items1, items2) && containItemsList(itemEqual, items2, items1);
}
