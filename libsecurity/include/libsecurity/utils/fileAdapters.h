#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

FILE *FileAdapters_Fopen(const char *fileName, const char *mode);
int16_t FileAdapters_Fclose(FILE *stream);
int16_t FileAdapters_Remove(const char *fileName);

#ifdef __cplusplus
}
#endif

#ifdef MBED_OS

#define DRIVE_PREFIX "sd"
#define MAX_FILE_PATH 255

#else

#endif
