#include "libsecurity/utils/fileAdapters.h"

#include "libsecurity/utils/utils.h"

#ifdef MBED_OS

#include <stdio.h>

#include "mbed-drivers/mbed.h"
#include "fileSystem/SDFileSystem/SDFileSystem.h"

extern "C" {

SDFileSystem sd(PTE3, PTE1, PTE2, PTE4, DRIVE_PREFIX); // MOSI, MISO, SCK, CS

FILE *FileAdapters_Fopen(const char *fileName, const char *mode) {
  char filePath[MAX_FILE_PATH];
  if (fileName == NULL || mode == NULL) return NULL;
  snprintf(filePath, sizeof(filePath), "/%s/%s", DRIVE_PREFIX, fileName);
  return fopen(filePath, mode);
}

int16_t FileAdapters_Fclose(FILE *stream) {
  return fclose(stream);
}

int16_t FileAdapters_Remove(const char *fileName) {
  char filePath[MAX_FILE_PATH];
  if (fileName == NULL) return -1;
  snprintf(filePath, sizeof(filePath), "/%s/%s", DRIVE_PREFIX, fileName);
  remove(filePath);
  return 0;
}
}

#else

extern "C" {


#include <stdio.h>

FILE *FileAdapters_Fopen(const char *fileName, const char *mode);
int16_t FileAdapters_Fclose(FILE *stream);
int16_t FileAdapters_Remove(const char *fileName);

FILE *FileAdapters_Fopen(const char *fileName, const char *mode) {
  char str[ERR_STR_LEN];
  snprintf(str, sizeof(str), "./%s", fileName);
  return Utils_Fopen(str, mode);
}

int16_t FileAdapters_Fclose(FILE *stream) {
  return (int16_t)Utils_Fclose(stream);
}

int16_t FileAdapters_Remove(const char *fileName) {
  char str[ERR_STR_LEN];
  snprintf(str, sizeof(str), "./%s", fileName);
  return (int16_t)Utils_RemoveFile(str);
}
}

#endif
