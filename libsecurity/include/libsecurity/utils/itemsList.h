#pragma once

#include "libsecurity/storage/secureStorage.h"

typedef struct { htab *Items; } ItemsHolder;

#define MIN_ITEM_NAME_LEN 1
#define MAX_ITEM_NAME_LEN 50

void ItemsList_New(ItemsHolder **items);
void ItemsList_Duplicate(ItemsHolder *src, ItemsHolder *dest);
bool ItemsList_ClearItem(void (*removeItem)(void *item), ItemsHolder *items, const char *name);
// int16_t ItemsList_NewClearItemByName(void (*removeItem)(void *item), htab
// **t, const char *name);
bool ItemsList_FreeItem(void (*removeItem)(void *item), ItemsHolder *items, const char *name);
void ItemsList_ClearAllItems(void (*removeItem)(void *item), ItemsHolder **items);
void ItemsList_FreeAllItems(void (*removeItem)(void *item), ItemsHolder *items);
bool ItemsList_AddItem(const ItemsHolder *items, const char *name, void *newItem);
bool ItemsList_CheckItem(const ItemsHolder *items, const char *name);
bool ItemsList_GetItem(const ItemsHolder *items, const char *name, void **item);
void ItemsList_Print(void (*printItem)(const char *header, const void *item), const char *str, const ItemsHolder *items);
void ItemsList_PrintKeys(const char *header, const ItemsHolder *items);
bool ItemsList_AddToStorage(bool (*storeItem)(const void *item, const SecureStorageS *storage, const char *data), const ItemsHolder *items,
                            const SecureStorageS *storage, const char *prefix);
bool ItemsList_LoadFromStorage(bool (*itemLoad)(void **item, const SecureStorageS *storage, const char *prefix, char **retName),
                               ItemsHolder **items, const SecureStorageS *storage, const char *prefix, void (*itemFree)(void *item));
bool ItemsList_IsEqual(bool (*itemEqual)(const void *item1, const void *item2), const ItemsHolder *items1, const ItemsHolder *items2);
