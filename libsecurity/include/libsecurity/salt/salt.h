#pragma once

#include "libsecurity/storage/secureStorage.h"
#include "libsecurity/password/password.h"

#define MIN_SALT_LEN 0
#define MAX_SALT_LEN 128

typedef struct {
  unsigned char *caSecret;
  unsigned char *caSalt;
  int16_t OutputLen; // Number of digits in the code. Default is 6
  int16_t Iterations; // Number of iterations to run the hash function, Default
  // is 64	Digest
  // func() hash.Hash // Digest type, Default is sha1
} SaltS;

void Salt_Print(FILE *ofp, const char *header, const SaltS *salt);
bool Salt_IsValid(const SaltS *salt);
bool Salt_NewSalt(SaltS **newSalt, const unsigned char *sSecret, const unsigned char *sSalt);
void Salt_FreeSalt(SaltS *salt);
bool Salt_Generate(const SaltS *salt, unsigned char **caNewPwd);
bool Salt_GenerateSaltedPassword(const unsigned char *sPwd, const unsigned char *sSalt, bool randomSalt, int16_t randomSaltLen, unsigned char **caNewPwd);
bool Salt_GenerateCharArraySaltedPassword(const unsigned char *caPwd, const unsigned char *caSalt, unsigned char **caNewPwd);
bool Salt_IsEqual(const SaltS *s1, const unsigned char *caPwd);
