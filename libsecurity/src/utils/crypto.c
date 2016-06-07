#include "libsecurity/utils/crypto_int.h"

#if defined(MBEDTLS_CRYPTO)

bool Crypto_CalcHmac(const unsigned char *key, int16_t keyLen, const unsigned char *input, size_t inputLen, unsigned char *output) {
  int16_t ret = 0;
  const mbedtls_md_info_t *mdInfo = NULL;
  mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if ((ret = mbedtls_md_hmac(mdInfo, key, keyLen, input, inputLen, output)) != 0) {
    snprintf(errStr, sizeof(errStr), "Error while calculating mbedtls_md_hmac, errIdx %d", ret);
    return false;
  }
  return true;
}

bool Crypto_EncryptDecryptAesCbc(int16_t mode, uint16_t len, const unsigned char *key, int16_t keyLen, const unsigned char iv[IV_LEN],
                                 const unsigned char *input, unsigned char *output) {
  int16_t textLen = len + Crypto_GetAesPadFactor(len), ret = -1;
  keyLen = keyLen << 3;
  unsigned char *newText = NULL, *newOutput = NULL, *outputPtr = NULL;
  unsigned char tmpIv[IV_LEN];
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  if (mode == CRYPTO_ENCRYPT_MODE) {
    ret = mbedtls_aes_setkey_enc(&ctx, key, keyLen);
    outputPtr = output;
  } else {
    ret = mbedtls_aes_setkey_dec(&ctx, key, keyLen);
    Utils_Malloc((void **)(&newOutput), textLen + 1); // output length will be padded
    // done by Utils_Malloc memset(newOutput, 0, textLen+1); // clear the memory
    outputPtr = newOutput;
  }
  if (ret != 0) {
    snprintf(errStr, sizeof(errStr), "Invalid key length %d, it must be 128, 192 or 256", (int16_t)keyLen * 8);
    return false;
  }
  Utils_Malloc((void **)(&newText), textLen + 1);
  // done by Utils_Malloc memset(newText, 0, textLen+1); // clear the memory
  memcpy(newText, input, len);
  memcpy(tmpIv, iv, IV_LEN);
  // not neded newText[len + 1] = 0;
  if (mbedtls_aes_crypt_cbc(&ctx, mode, (size_t)(textLen), tmpIv, newText, outputPtr) != 0) {
    snprintf(errStr, sizeof(errStr), "Invalid input length %d to encrypt, maximum length must be divided by 16", (int16_t)len);
    Utils_Free(newText);
    Utils_Free(newOutput);
    return false;
  }
  if (mode == CRYPTO_DECRYPT_MODE) { // the return must be the original length before padding
    memcpy(output, newOutput, len + 1);
  }
  Utils_Free(newText);
  Utils_Free(newOutput);
  return true;
}

bool Crypto_SHA256(const unsigned char *key, int16_t keyLen, unsigned char *output) {
  mbedtls_sha256(key, keyLen, output, false);
  return true;
}

int16_t Crypto_GetAesPadFactor(int16_t textLen) {
  return (MBED_AES_BLOCK_SIZE - textLen % MBED_AES_BLOCK_SIZE) % MBED_AES_BLOCK_SIZE;
}

#else

bool Crypto_CalcHmac(const unsigned char *key, int16_t keyLen, const unsigned char *input, size_t inputLen, unsigned char *output) {
  crypto_auth_hmacsha256(output, input, (unsigned long long)inputLen, key);
  if (keyLen < 0) return false;
  return true;
}

bool Crypto_EncryptDecryptAesCbc(int16_t mode, uint16_t len, const unsigned char *key, int16_t keyLen, const unsigned char iv[IV_LEN],
                                 const unsigned char *input, unsigned char *output) {
  if ((mode != CRYPTO_ENCRYPT_MODE && mode != CRYPTO_DECRYPT_MODE) || keyLen < 0) return false;
  crypto_stream_xor(output, input, (unsigned long long)len, iv, key);
  return true;
}

bool Crypto_SHA256(const unsigned char *key, int16_t keyLen, unsigned char *output) {
  crypto_hash(output, key, keyLen);
  return true;
}

int16_t Crypto_GetAesPadFactor(int16_t textLen) {
  if (textLen != 0) // to get rid of the Wall warning
    return 0;
  else
    return textLen;
}

#endif

bool Crypto_Random(unsigned char *random, int16_t len) {
#if defined(MBED_OS)
  return DTLS_GetRandom(random, len); // it is using mbed cpp implementation
#elif defined(NaCl_CRYPTO)
  randombytes(random, len);
  return true;
#else // LINUX_OS on BBB
  FILE *fp;
  if ((fp = fopen("/dev/urandom", "r")) == NULL) {
    snprintf(errStr, sizeof(errStr), "Can't open /dev/urandom");
    return false;
  }
  if ((int16_t)fread((void *)random, 1, len, fp) != len) {
    snprintf(errStr, sizeof(errStr), "Can't read %d random bytes from /dev/urandom", len);
    fclose(fp);
    return false;
  }
  fclose(fp);
  return true;
#endif
}
