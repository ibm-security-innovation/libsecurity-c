// One time password implemenatation
//==================================
// This package implements RFC 6238 "TotpS: Time-Based One-Time Password
// Algorithm"
// and RFC 4226 HOTP: "An HMAC-Based One-Time Password Algorithm"
// * OTP() implements the lower level common layer
// * TotpS() (time based OTP) and HOTP (counter based OTP) implement the upper
// layers.
//
// Comments:
//  1. Illegal operations:
//     1.1. An empty secret key
//     1.2. Code length other than 6-8 digits (not protected by the code)
//     1.3. Digest other than MD4, MD5, SHA1, SHA256 or SHA512 (not defined by
//     the RFC)  (not protected by the code)
//  2. The encoding scheme of the secret key is not define by the RFC.
//     It's the user's responsability to use a legal secret key. The most common
//     encoding scheme is base32 (as used by the Google Authenticator), therefor
//     the testing of the code includes converting a string to a legal base32
//     encoded string.
//  3. The option for resetting a HOTP counter to another value of counter is
//  currently not implemented as it is defined as an extension in the RFC
#include "libsecurity/otp/otp_int.h"

bool Otp_TestMode = false;

void Otp_Print(FILE *ofp, const char *header, const OtpS *otp) {
  fprintf(ofp, "%s", header); // print the header no meter what is the value of th otp
  if (otp == NULL) return;
  fprintf(ofp, "Otp: Digits: %d\n", otp->Digits);
}

STATIC bool isValidDigits(int16_t val) {
  int16_t len = MAX_NUM_OF_DIGITS;

  if (len > crypto_auth_BYTES) len = crypto_auth_BYTES;
  if (val < MIN_NUM_OF_DIGITS || val > len) {
    snprintf(errStr, sizeof(errStr), "The OTP struct is not valid, the used number of digits %d is "
                                     "not valid in must be between %d-%d",
             val, MIN_NUM_OF_DIGITS, len);
    assert(LIB_NAME "OTP structure, number of digits is not valid" && (false || Otp_TestMode));
    return false;
  }
  return true;
}

// The digest must be one of SHA1, SHA256 and SHA512
STATIC bool isValidDigest(int16_t val) {
  if (val < MIN_DIGEST_IDX || val > MAX_DIGEST_IDX) {
    snprintf(errStr, sizeof(errStr), "The OTP struct is not valid, the used "
                                     "digest index %d is not in the range %d-%d",
             val, MIN_DIGEST_IDX, MAX_DIGEST_IDX);
    assert(LIB_NAME "OTP structure, digest type is not valid" && (false || Otp_TestMode));
    return false;
  }
  return true;
}

STATIC bool isValidOtpSecret(const unsigned char *secret) {
  int16_t len = 0;

  if (secret == NULL) return false;
  len = strlen((const char *)secret);
  if (len < MIN_SECRET_LEN || len > MAX_SECRET_LEN) {
    snprintf(errStr, sizeof(errStr), "The secret key has an illegal length (%d), "
                                     "the length must be between %d and %d",
             len, MIN_SECRET_LEN, MAX_SECRET_LEN);
    assert(LIB_NAME "OTP structure, secret is not valid" && (false || Otp_TestMode));
    return false;
  }
  return true;
}

STATIC bool isValidOtp(const OtpS *otp) {
  if (isValidDigits(otp->Digits) == false) return false;
  if (isValidDigest(otp->DigestType) == false) return false;
  return true;
}

// set he secret string to be exactly crypto_auth_BYTES bytes
STATIC bool setSecretStr(unsigned char fixedSecret[crypto_auth_BYTES + 1], const unsigned char *secret) {
  int16_t sLen = 0;

  if (secret == NULL) {
    assert(LIB_NAME "secret string must not be NULL" && (false || Otp_TestMode));
    return false;
  }
  sLen = strlen((const char *)secret);
  if (sLen > crypto_auth_BYTES) sLen = crypto_auth_BYTES;
  memset(fixedSecret, '0', crypto_auth_BYTES);
  memcpy(&(fixedSecret[crypto_auth_BYTES - sLen]), secret, sLen);
  fixedSecret[crypto_auth_BYTES] = 0;
  return true;
}

// Generate Otp
bool Otp_NewAdvance(OtpS **otp, const unsigned char *secret, int16_t numOfDigits, int16_t digestType) {
  unsigned char *secretStr, fixedSecret[crypto_auth_BYTES + 1];

  if (isValidOtpSecret(secret) == false) return false;
  if (isValidDigits(numOfDigits) == false) return false;
  if (isValidDigest(digestType) == false) return false;
  setSecretStr(fixedSecret, secret);
  Utils_Malloc((void **)(otp), sizeof(OtpS));
  Utils_CreateAndCopyUcString(&secretStr, fixedSecret, strlen((const char *)fixedSecret));
  (*otp)->Secret = secretStr;
  (*otp)->Digits = numOfDigits;
  (*otp)->DigestType = digestType;
  return true;
}

// The default OTP: sha1 with 6 digits
// Any number of digits and any (hash) function are allowed
bool Otp_New(OtpS **otp, const unsigned char *secret) {
  if (isValidOtpSecret(secret) == false) return false;
  return Otp_NewAdvance(otp, secret, DEFAULT_NUM_OF_DIGITS, DEFAULT_HASH_FUNC_IDX);
}

void Otp_Free(OtpS *otp) {
  if (otp == NULL) return;
  Utils_Free(otp->Secret);
  Utils_Free(otp);
}

// Return the OTP for a given input
STATIC bool generateHmac(const OtpS *otp, char *key, char **val) {
  int16_t mask = 0xf, offset = 0, len = crypto_auth_BYTES, sLen = 0;
  int32_t code;
  unsigned char digest[crypto_auth_BYTES], secret[crypto_auth_BYTES + 1];
  char fmt[10];

  if (otp == NULL || key == NULL || otp->Secret == NULL) {
    snprintf(errStr, sizeof(errStr), "OTP: generateHmac, The OTP, secret and key must not be NULL");
    assert(LIB_NAME "OTP structure, OTP secret and key strings must not be NULL" && (false || Otp_TestMode));
    return false;
  }
  setSecretStr(secret, otp->Secret);
  // verify key and secret before call to crypto_auth_hmacsha256
  if ((sLen = strlen((char *)secret)) != crypto_auth_BYTES) {
    snprintf(errStr, sizeof(errStr), "The secret length %d is not legal, it must be exactly %d", sLen, crypto_auth_BYTES);
    return false;
  }
  if ((sLen = strlen((char *)key)) != crypto_auth_BYTES) {
    snprintf(errStr, sizeof(errStr), "The key length %d is not legal, it must be exactly %d", sLen, crypto_auth_BYTES);
    return false;
  }
  Crypto_CalcHmac(secret, sLen, (unsigned char *)key, (int16_t)strlen(key), digest);
  offset = (digest[len - 1] & mask);
  code = (int32_t)(digest[offset] & 0x7f) << 24 | (int32_t)(digest[offset + 1] & 0xff) << 16 | (int32_t)(digest[offset + 2] & 0xff) << 8 |
         (int32_t)(digest[offset + 3] & 0xff);
  code = (int32_t)(((int64_t)code) % ((int64_t)(pow(10, otp->Digits) + 0.5))); // maximum number of
  // digits is 10, therefore long is good enogth
  Utils_Malloc((void **)(val), otp->Digits + 1);
  snprintf(fmt, sizeof(fmt), "%%0%dd", otp->Digits);
  snprintf(*val, otp->Digits, fmt, code);
  debug_print("Key '%s' secret '%s' code '%s' digest %d\n", key, otp->Secret, *val, otp->DigestType);
  return true;
}

// A counter that is incremented each lifespan - all times within the same timespan return the same value,
// once the time is incremented by the defined lifespan the return value is incremented as well
STATIC MicroSecTimeStamp timeCode(const TotpS *tp, MicroSecTimeStamp t) {
  if (tp == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error in timeCode, tp was not set, use timeCode of 1");
    if (Otp_TestMode == false) fprintf(stderr, "%s\n", errStr);
    assert(LIB_NAME "OTP TOTP structure must not be NULL" && (false || Otp_TestMode));
    return 1;
  }
  if (tp->Interval == 0) {
    snprintf(errStr, sizeof(errStr), "Internal error in timeCode, interval was set to ilegal value of "
                                     "0, use timeCode of 1");
    fprintf(stderr, "%s\n", errStr);
    return 1;
  }
  return (t / tp->Interval);
}

// Return the OTP for a given input
// Input may either be time (for TotpS) or integer (for HotpS)
bool Otp_Generate(const OtpS *otp, int64_t seed, char **val) {
  int16_t len = 32 + 1;
  char str[len];

  if (otp == NULL) return false;
  if (isValidOtp(otp) == false) return false;
  snprintf(str, len, "%032ld", (long int)seed); // 32 is the size of crypto_auth_KEYBYTES
  return generateHmac(otp, str, val);
}

bool Otp_IsEqual(const OtpS *otp1, const OtpS *otp2) {
  if (otp1 == NULL || otp2 == NULL) return false;
  if (otp1->Secret == NULL || otp2->Secret == NULL) // uninitiated secret => not a legal OTP
    return false;
  return (otp1->Digits == otp2->Digits && otp1->DigestType == otp2->DigestType && strcmp((char *)otp1->Secret, (char *)otp2->Secret) == 0);
}

// If the secret was used, The memory used by the old secret must be free first
bool Otp_ReplaceSecret(OtpS *otp, const unsigned char *secret) {
  unsigned char *secretStr = NULL;

  if (otp == NULL || secret == NULL || isValidOtpSecret(secret) == false) return false;
  if (otp->Secret != NULL) Utils_Free(otp->Secret);
  Utils_CreateAndCopyUcString(&secretStr, secret, strlen((const char *)secret));
  otp->Secret = secretStr;
  return true;
}

//------------------------------------------------------

void Otp_PrintTotp(FILE *ofp, const char *header, const TotpS *totp) {
  fprintf(ofp, "%s", header); // header will be print even if the structure is empty
  if (totp == NULL) return;
  fprintf(ofp, "Totp: Interval: %d, Base OTP:", totp->Interval);
  Otp_Print(ofp, "", totp->BaseOtp);
}

STATIC void totpStructToStr(const TotpS *totp, char *str, int16_t maxStrLen) {
  snprintf(str, maxStrLen, TOTP_STRUCT_FMT, totp->BaseOtp->Secret, totp->BaseOtp->Digits, totp->BaseOtp->DigestType, totp->Interval);
}

STATIC bool isValidInterval(int16_t val) {
  if (val < MIN_INTERVAL_SEC || val > MAX_INTERVAL_SEC) {
    snprintf(errStr, sizeof(errStr), "The TOTP struct is not valid, the interval "
                                     "%d must be between %d-%d seconds",
             val, MIN_INTERVAL_SEC, MAX_INTERVAL_SEC);
    assert(LIB_NAME "OTP TOTP interval is not valid" && (false || Otp_TestMode));
    return false;
  }
  return true;
}

STATIC bool isValidTotp(const TotpS *totp) {
  if (totp == NULL) {
    assert(LIB_NAME "OTP TOTP structure must not be NULL" && (false || Otp_TestMode));
    return false;
  }
  return (isValidInterval(totp->Interval));
}

// Default lifespan of a TotpS is 30 seconds
bool Otp_NewTotp(TotpS **totp, const unsigned char *secret) {
  if (isValidOtpSecret(secret) == false) return false;
  Utils_Malloc((void **)(totp), sizeof(TotpS));
  if (Otp_New(&((*totp)->BaseOtp), secret) == false) return false;
  (*totp)->Interval = DEFAULT_INTERVAL_SEC;
  return true;
}

void Otp_FreeTotp(TotpS *totp) {
  if (totp == NULL) return;
  Otp_Free(totp->BaseOtp);
  Utils_Free(totp);
}

// Generate an OTP for a given time
bool Otp_GetTotpAtTime(const TotpS *totp, MicroSecTimeStamp t, char **val) {
  MicroSecTimeStamp sec = timeCode(totp, t);

  if (isValidTotp(totp) == false) {
    return false;
  }
  return Otp_Generate(totp->BaseOtp, sec, val);
}

// Return the Time Based One Time Password for the current time
bool Otp_GetTotpNow(const TotpS *totp, char **val) {
  return Otp_GetTotpAtTime(totp, Utils_GetTimeNowInSec(), val);
}

bool Otp_IsEqualTotp(const TotpS *totp1, const TotpS *totp2) {
  if (totp1 == NULL || totp2 == NULL) return false;
  return (totp1->Interval == totp2->Interval && Otp_IsEqual(totp1->BaseOtp, totp2->BaseOtp) == true);
}

bool Otp_StoreTotp(const TotpS *totp, const SecureStorageS *storage, const char *prefix) {
  int16_t otpStrLen = MAX_OTP_STR_LEN, prefixLen = 0;
  char *totpStr = NULL;
  char *key = NULL;

  if (totp == NULL || storage == NULL || prefix == NULL) return false;
  prefixLen = strlen(prefix) + strlen(TOTP_PREFIX) + 1;
  if (Utils_IsPrefixValid("Otp_StoreTotp", prefix) == false) return false;
  Utils_Malloc((void **)(&totpStr), otpStrLen + 1);
  totpStructToStr(totp, totpStr, otpStrLen);
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, OTP_PREFIX_FMT, TOTP_PREFIX, prefix);
  debug_print("Otp store: Write key '%s' val '%s'\n", key, totpStr);
  if (SecureStorage_AddItem(storage, (unsigned char *)key, strlen(key), (unsigned char *)totpStr, strlen(totpStr)) == false) {
    Utils_Free(key);
    Utils_Free(totpStr);
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", key, totpStr);
    return false;
  }
  Utils_Free(key);
  Utils_Free(totpStr);
  return true;
}

bool Otp_LoadTotp(void **totp, const SecureStorageS *storage, const char *prefix, char **retName) {
  int digits, digestType, interval, prefixLen = 0; // to avoid mbed compiler warnnings
  unsigned char *val = NULL, *key = NULL;
  unsigned char secret[MAX_SECRET_LEN];

  *retName = NULL;
  if (storage == NULL) {
    snprintf(errStr, sizeof(errStr), "Storage must initiated first");
    return false;
  }
  if (prefix == NULL) {
    snprintf(errStr, sizeof(errStr), "Prefix must not be NULL");
    return false;
  }
  prefixLen = strlen(prefix) + strlen(TOTP_PREFIX) + 1;
  if (Utils_IsPrefixValid("Otp_LoadTotp", prefix) == false) return false;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf((char *)key, prefixLen, OTP_PREFIX_FMT, TOTP_PREFIX, prefix);
  if (SecureStorage_GetItem(storage, key, strlen((char *)key), &val) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: Read from secure storage key '%s' not found", key);
    debug_print("Internal Error: Read from secure storage key '%s' not found", key);
    Utils_Free(key);
    return false;
  }
  debug_print("read: key: '%s' totp info '%s'\n", key, val);
  sscanf((char *)val, TOTP_STRUCT_FMT, secret, &digits, &digestType, &interval);
  debug_print("Load data for totp: '%s', %d %d %d\n", secret, digits, digestType, interval);
  if (Otp_NewTotp((TotpS **)totp, secret) == false) {
    printf("Error: %s\n", errStr);
    return false;
  }
  (*((TotpS **)totp))->BaseOtp->Digits = digits;
  (*((TotpS **)totp))->BaseOtp->DigestType = digestType;
  (*((TotpS **)totp))->Interval = interval;
  if (OTP_DEBUG) {
    Otp_PrintTotp(stderr, "loaded totp:\n", *(TotpS **)totp);
  }
  Utils_Free(key);
  Utils_Free(val);
  return true;
}

//-----------------------------------------------

void Otp_PrintHotp(FILE *ofp, const char *header, const HotpS *hotp) {
  fprintf(ofp, "%s", header); // The header will be printed even if the hotp is NULL
  if (hotp == NULL) return;
  fprintf(ofp, "Hotp: count: %ld, Base OTP:", (long int)hotp->Count);
  Otp_Print(ofp, "", hotp->BaseOtp);
}

STATIC void hotpStructToStr(const HotpS *hotp, char *str, int16_t maxStrLen) {
  if (hotp == NULL || str == NULL) {
    assert(LIB_NAME "OTP HOTP structure and input string must not be NULL" && (false || Otp_TestMode));
  }
  snprintf(str, maxStrLen, HOTP_STRUCT_FMT, hotp->BaseOtp->Secret, hotp->BaseOtp->Digits, hotp->BaseOtp->DigestType, (long int)hotp->Count);
}

bool Otp_NewHotp(HotpS **hotp, const unsigned char *secret, int64_t count) {
  if (isValidOtpSecret(secret) == false) {
    return false;
  }
  Utils_Malloc((void **)(hotp), sizeof(HotpS));
  if (Otp_New(&((*hotp)->BaseOtp), secret) == false) return false;
  (*hotp)->Count = count;
  return true;
}

void Otp_FreeHotp(HotpS *hotp) {
  if (hotp == NULL) return;
  Otp_Free(hotp->BaseOtp);
  Utils_Free(hotp);
}

// Generate an OTP for a given value
bool Otp_GetHotpAtCount(HotpS *hotp, int64_t count, char **val) {
  return Otp_Generate(hotp->BaseOtp, count, val);
}

// Generate the next OTP in the sequence
bool Otp_GetHotpNext(HotpS *hotp, char **val) {
  if (hotp == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: Otp_GetHotpNext, structure was not initiated\n");
    fprintf(stderr, "%s\n", errStr);
    return false;
  }
  hotp->Count++;
  return Otp_GetHotpAtCount(hotp, hotp->Count, val);
}

// Generate a new OTP using a random integer
bool Otp_HotpRandom(HotpS *hotp, char **val) {
  int16_t i;
  int64_t count = 0;
  unsigned char random[RANDOM_LEN];

  if (hotp == NULL) {
    snprintf(errStr, sizeof(errStr), "Internal error: Otp_HotpRandom, structure was not initiated\n");
    fprintf(stderr, "%s\n", errStr);
    return false;
  }
  Crypto_Random(random, RANDOM_LEN);
  for (i = RANDOM_LEN - 1; i >= 0; i--) {
    count = (count << 8) + random[i];
  }
  return Otp_GetHotpAtCount(hotp, count, val);
}

bool Otp_IsEqualHotp(const HotpS *hotp1, const HotpS *hotp2) {
  if (hotp1 == NULL || hotp2 == NULL) {
    return false;
  }
  return (hotp1->Count == hotp2->Count && Otp_IsEqual(hotp1->BaseOtp, hotp2->BaseOtp) == true);
}

bool Otp_StoreHotp(const HotpS *hotp, const SecureStorageS *storage, const char *prefix) {
  int16_t otpStrLen = MAX_OTP_STR_LEN, prefixLen = 0;
  char *hotpStr = NULL, *key = NULL;

  if (hotp == NULL || storage == NULL || prefix == NULL) return false;
  prefixLen = strlen(prefix) + strlen(HOTP_PREFIX) + 1;
  if (Utils_IsPrefixValid("Otp_StoreHotp", prefix) == false) return false;
  Utils_Malloc((void **)(&hotpStr), otpStrLen + 1);
  hotpStructToStr(hotp, hotpStr, otpStrLen);
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf(key, prefixLen, OTP_PREFIX_FMT, HOTP_PREFIX, prefix);
  debug_print("Otp_StoreHotp write key '%s' val '%s'\n", key, hotpStr);
  if (SecureStorage_AddItem(storage, (unsigned char *)key, strlen(key), (unsigned char *)hotpStr, strlen(hotpStr)) == false) {
    snprintf(errStr, sizeof(errStr), "Can't add item '%s' value '%s' to storage", key, hotpStr);
    Utils_Free(hotpStr);
    Utils_Free(key);
    return false;
  }
  Utils_Free(key);
  Utils_Free(hotpStr);
  return true;
}

bool Otp_LoadHotp(void **hotp, const SecureStorageS *storage, const char *prefix, char **retName) {
  int digits, digestType, prefixLen = 0; // to avoid mbed compiler warnnings
  long count;
  unsigned char *val = NULL;
  unsigned char *key = NULL, secret[MAX_SECRET_LEN];

  *retName = NULL;
  if (storage == NULL) {
    snprintf(errStr, sizeof(errStr), "Storage must initiated first");
    return false;
  }
  if (prefix == NULL) {
    snprintf(errStr, sizeof(errStr), "Prefix must not be NULL");
    return false;
  }
  prefixLen = strlen(prefix) + strlen(HOTP_PREFIX) + 1;
  if (Utils_IsPrefixValid("Otp_LoadHotp", prefix) == false) return false;
  Utils_Malloc((void **)(&key), prefixLen);
  snprintf((char *)key, prefixLen, OTP_PREFIX_FMT, HOTP_PREFIX, prefix);
  if (SecureStorage_GetItem(storage, key, strlen((char *)key), &val) == false) {
    snprintf(errStr, sizeof(errStr), "Internal Error: Read from secure storage key '%s' not found", key);
    debug_print("Internal Error: Read from secure storage key '%s' not found\n", key);
    Utils_Free(key);
    return false;
  }
  debug_print("read: key: '%s' hotp info '%s'\n", key, val);
  sscanf((char *)val, HOTP_STRUCT_FMT, secret, &digits, &digestType, &count);
  debug_print("Load data for hotp: '%s', %d %d %ld\n", secret, digits, digestType, count);
  if (Otp_NewHotp((HotpS **)hotp, secret, count) == false) {
    printf("Error: %s\n", errStr);
    return false;
  }
  (*((HotpS **)hotp))->BaseOtp->Digits = digits;
  (*((HotpS **)hotp))->BaseOtp->DigestType = digestType;
  (*((HotpS **)hotp))->Count = count;
  if (OTP_DEBUG) {
    Otp_PrintHotp(stderr, "loaded hotp:\n", *(HotpS **)hotp);
  }
  Utils_Free(key);
  Utils_Free(val);
  return true;
}
