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

int Crypto_EncryptDecryptAesCbc(int16_t mode, uint16_t len, const unsigned char *key, int16_t keyLen, unsigned char iv[IV_LEN],
                                 const unsigned char *input, unsigned char *output) {
  int16_t textLen = len + Crypto_GetAesPadFactor(len), ret = -1;
  keyLen = keyLen << 3;
  unsigned char newOutput[NaCl_MAX_TEXT_LEN_BYTES+1];
  unsigned char *outputPtr = NULL;
  unsigned char tmpIv[IV_LEN];
  mbedtls_aes_context ctx;

  mbedtls_aes_init(&ctx);
  if (mode == CRYPTO_ENCRYPT_MODE) {
    ret = mbedtls_aes_setkey_enc(&ctx, key, keyLen);
    outputPtr = output;
  } else {
    ret = mbedtls_aes_setkey_dec(&ctx, key, keyLen);
    outputPtr = newOutput;
  }
  if (ret != 0) {
    snprintf(errStr, sizeof(errStr), "Invalid key length %d, it must be 128, 192 or 256", (int16_t)keyLen * 8);
    return false;
  }
  memcpy(tmpIv, iv, IV_LEN);
  if (mbedtls_aes_crypt_cbc(&ctx, mode, (size_t)(textLen), tmpIv, input, outputPtr) != 0) {
    snprintf(errStr, sizeof(errStr), "Invalid input length %d to encrypt, maximum length must be divided by 16", (int16_t)len);
    return false;
  }
  if (mode == CRYPTO_DECRYPT_MODE) { // the return must be the original length before padding
    newOutput[len] = 0;
    memcpy(output, newOutput, len + 1);
  }
  return len;
}

bool Crypto_SHA256(const unsigned char *key, int16_t keyLen, unsigned char *output) {
  mbedtls_sha256(key, keyLen, output, false);
  return true;
}

int16_t Crypto_GetAesPadFactor(int16_t textLen) {
  return (MBED_AES_BLOCK_SIZE - textLen % MBED_AES_BLOCK_SIZE) % MBED_AES_BLOCK_SIZE;
}

#elif defined(OPENSSL_CRYPTO)

bool Crypto_CalcHmac(const unsigned char *key, int16_t keyLen, const unsigned char *input, size_t inputLen, unsigned char *output) {
  memcpy(output, HMAC(EVP_sha256(), key, keyLen, input, inputLen, NULL, NULL), SHA256_LEN);
  return true;
}

int Crypto_EncryptDecryptAesCbc(int16_t mode, uint16_t inputLen, const unsigned char *key, int16_t keyLen, unsigned char iv[IV_LEN],
                                 const unsigned char *input, unsigned char *output) {
  EVP_CIPHER_CTX *ctx;
  int len, outputLen;

  if(!(ctx = EVP_CIPHER_CTX_new())) {
    snprintf(errStr, sizeof(errStr), "Crypto_EncryptDecryptAesCbc error when creating EVP_CIPHER_CTX_new");
    return -1;
  }
  if (mode == CRYPTO_ENCRYPT_MODE) {
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
      snprintf(errStr, sizeof(errStr), "Crypto_EncryptDecryptAesCbc error when executing EVP_EncryptInit_ex");
      return -1;
    }
    if(EVP_EncryptUpdate(ctx, output, &len, input, inputLen) != 1) {
      snprintf(errStr, sizeof(errStr), "Crypto_EncryptDecryptAesCbc error when executing EVP_EncryptUpdate");
      return -1;
    }
    outputLen = len;
    if(EVP_EncryptFinal_ex(ctx, output + len, &len) != 1) {
      snprintf(errStr, sizeof(errStr), "Crypto_EncryptDecryptAesCbc error when executing EVP_EncryptFinal_ex");
      return -1;
    }
    outputLen += len;
  }else {
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
      snprintf(errStr, sizeof(errStr), "Crypto_EncryptDecryptAesCbc error when executing EVP_DecryptInit_ex");
      return -1;
    }
    if(EVP_DecryptUpdate(ctx, output, &len, input, inputLen) != 1) {
      snprintf(errStr, sizeof(errStr), "Crypto_EncryptDecryptAesCbc error when executing EVP_DecryptUpdate");
      return -1;
    }
    outputLen = len;
    if(EVP_DecryptFinal_ex(ctx, output + len, &len) != 1) {
      snprintf(errStr, sizeof(errStr), "Crypto_EncryptDecryptAesCbc error when executing EVP_DecryptFinal_ex");
      return -1;
    }
    outputLen += len;
    output[outputLen] = 0;
  }
  EVP_CIPHER_CTX_free(ctx);
  return outputLen;
}

bool Crypto_SHA256(const unsigned char *key, int16_t keyLen, unsigned char *output) {
  SHA256(key, keyLen, output);
  return true;
}

int16_t Crypto_GetAesPadFactor(int16_t textLen) {
  return 0;
}

#else

bool Crypto_CalcHmac(const unsigned char *key, int16_t keyLen, const unsigned char *input, size_t inputLen, unsigned char *output) {
  crypto_auth_hmacsha256(output, input, (unsigned long long)inputLen, key);
  if (keyLen < 0) return false;
  return true;
}

int Crypto_EncryptDecryptAesCbc(int16_t mode, uint16_t len, const unsigned char *key, int16_t keyLen, unsigned char iv[IV_LEN],
                                 const unsigned char *input, unsigned char *output) {
  if ((mode != CRYPTO_ENCRYPT_MODE && mode != CRYPTO_DECRYPT_MODE) || keyLen < 0) return false;
  crypto_stream_xor(output, input, (unsigned long long)len, iv, key);
  return len;
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
