#pragma once

#include "libsecurity/utils/utils.h"

#if defined(MBED_OS) || defined(MBEDTLS_CRYPTO)

#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/aes.h"
#include "mbedtls/havege.h"

#include "mbedtls/sha256.h"

#define SHA256_LEN 32
#define IV_LEN 16
#define AES_OUTPUT_LEN 32
#define crypto_auth_BYTES 32
#define crypto_hash_BYTES 32

#define ALIGN_FACTOR UTILS_STR_LEN_SIZE

#define MBED_AES_BLOCK_SIZE 16

#define CRYPTO_ENCRYPT_MODE MBEDTLS_AES_ENCRYPT
#define CRYPTO_DECRYPT_MODE MBEDTLS_AES_DECRYPT

#define NaCl_MAX_TEXT_LEN_BYTES 256

#define SECRET_LEN 32

#endif

#if defined(NaCl_CRYPTO)

#include "crypto_hash.h"
#include "crypto_auth.h"
#include "crypto_auth_hmacsha256.h"
#include "randombytes.h"
#include "crypto_stream.h"
#include "crypto_hash_sha256.h"
#include "crypto_hash_sha512.h"

#define SHA256_LEN crypto_hash_sha256_BYTES
#define IV_LEN crypto_stream_NONCEBYTES
#define AES_OUTPUT_LEN crypto_stream_KEYBYTES

#define ALIGN_FACTOR 0

#define CRYPTO_ENCRYPT_MODE 0
#define CRYPTO_DECRYPT_MODE 1

// max text length is 89 B
#define NaCl_MAX_TEXT_LEN_BYTES 256

// secret and iv len are mandatory in NaCl
#define SECRET_LEN crypto_stream_KEYBYTES // 32

#endif

// IV string prefix is its length
#define FULL_IV_LEN (IV_LEN + UTILS_STR_LEN_SIZE)

bool Crypto_CalcHmac(const unsigned char *key, int16_t keyLen, const unsigned char *input, size_t inputLen, unsigned char *output);
bool Crypto_EncryptDecryptAesCbc(int16_t mode, uint16_t len, const unsigned char *key, int16_t keyLen, const unsigned char iv[IV_LEN],
                                 const unsigned char *input, unsigned char *output);
bool Crypto_SHA256(const unsigned char *key, int16_t keyLen, unsigned char *output);
bool Crypto_Random(unsigned char *random, int16_t len);
int16_t Crypto_GetAesPadFactor(int16_t textLen);
