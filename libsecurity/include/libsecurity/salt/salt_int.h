#pragma once

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "libsecurity/utils/crypto.h"
#include "libsecurity/utils/utils.h"
#include "libsecurity/salt/salt.h"

#define DEFAULT_OUTPUT_LEN 40
#define DEFAULT_SALT_LEN 8
#define DEFAULT_NUM_OF_ITERATIONS 1

#define MIN_OUTPUT_LEN 6
#define MAX_OUTPUT_LEN 512
#define MIN_SECRET_LEN 4
#define MAX_SECRET_LEN 255
#define MIN_NUM_OF_ITERATIONS 1

extern bool Salt_TestMode;

STATIC bool isValidOutputLen(int16_t val);
STATIC bool isValidSaltSecret(const unsigned char *caSecret);
STATIC bool isValidSalt(const unsigned char *caSalt);
STATIC bool isValidNumOfIterations(int16_t val);
STATIC bool getRandomSalt(int16_t len, unsigned char **caNewSalt);
