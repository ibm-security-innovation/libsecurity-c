#pragma once

#include "libsecurity/utils/utils.h"

#define AES_BLOCK_SIZE 16

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

#define SECRET_LEN 32

#endif

#if defined(OPENSSL_CRYPTO)

#include <openssl/aes.h> 
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define IV_LEN AES_BLOCK_SIZE

#define SHA256_LEN 32
#define crypto_auth_BYTES 32
#define crypto_hash_BYTES 32

#define ALIGN_FACTOR 0

#define CRYPTO_ENCRYPT_MODE AES_ENCRYPT
#define CRYPTO_DECRYPT_MODE AES_DECRYPT

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

// secret and iv len are mandatory in NaCl
#define SECRET_LEN crypto_stream_KEYBYTES // 32

#endif

#define NaCl_MAX_TEXT_LEN_BYTES 256

// IV string prefix is its length
#define FULL_IV_LEN (IV_LEN + UTILS_STR_LEN_SIZE)

bool Crypto_CalcHmac(const unsigned char *key, int16_t keyLen, const unsigned char *input, size_t inputLen, unsigned char *output);
int Crypto_EncryptDecryptAesCbc(int16_t mode, uint16_t len, const unsigned char *key, int16_t keyLen, unsigned char iv[IV_LEN],
                                 const unsigned char *input, unsigned char *output);
bool Crypto_SHA256(const unsigned char *key, int16_t keyLen, unsigned char *output);
bool Crypto_Random(unsigned char *random, int16_t len);
int16_t Crypto_GetAesPadFactor(int16_t textLen);
