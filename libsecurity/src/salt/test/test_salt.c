#include "libsecurity/salt/salt_int.h"

#define NUM_OF_TESTS 400
#define DEFAULT_PASSWORD "a1b2c3d"
#define DEFAULT_SALT "salt1234"

typedef struct {
  SaltS *S;
  unsigned char *Res;
} SaltRunS;

SaltRunS refRunsSalt[NUM_OF_TESTS];
int16_t NumOfTestsCnt = 0;

STATIC bool testInitRefSalt() {
  int16_t i = 0, j = 0, ol = 0, iter = 0, randomLen = 20;
  bool ret = false, pass = true;
  bool secretOk = false, saltOk = false, olOk = false, iterOk = false;
  int16_t sLen = 3, saltLen = 3, saltStrLen = 0, secretStrLen = 0;
  bool clearS = false, clearSalt = false;
  char *secrets[] = { "", "ABCD", "place holder for random" };
  unsigned char *newPwd = NULL, *nSalt = NULL, *nSecret = NULL, *secretR = NULL, *saltR = NULL;
  char *salts[] = { "", "a12b34", "place holder for random" };
  char *sPtr = NULL, *saltPtr = NULL;
  SaltS *s;

  for (i = 0; i < sLen; i++) {
    if (i == sLen - 1) {
      getRandomSalt(randomLen, &secretR);
      sPtr = (char *)secretR;
      secretStrLen = randomLen;
      clearS = true;
    } else {
      sPtr = secrets[i];
      secretStrLen = strlen(sPtr);
      secretR = NULL;
      clearS = false;
    }
    for (j = 0; j < saltLen; j++) {
      if (j == saltLen - 1) {
        getRandomSalt(randomLen, &saltR);
        saltPtr = (char *)saltR;
        saltStrLen = randomLen;
        clearSalt = true;
      } else {
        saltPtr = salts[j];
        saltStrLen = strlen(saltPtr);
        saltR = NULL;
        clearSalt = false;
      }
      for (ol = 0; ol < MAX_OUTPUT_LEN; ol += 20) {
        for (iter = MIN_NUM_OF_ITERATIONS - 1; iter < MIN_NUM_OF_ITERATIONS * 30; iter += 10) {
          Utils_GenerateCharArray((unsigned char *)sPtr, secretStrLen, &nSecret);
          secretOk = isValidSaltSecret(nSecret);
          Utils_Free(nSecret);
          Utils_GenerateCharArray((unsigned char *)saltPtr, saltStrLen, &nSalt);
          saltOk = isValidSalt(nSalt);
          Utils_Free(nSalt);
          ret = Salt_NewSalt(&s, (unsigned char *)sPtr, (unsigned char *)saltPtr);
          if (ret == true && (secretOk == false || saltOk == false)) {
            printf("testInitRefSalt fail: Initialize failed: initialize was "
                   "done successfully but "
                   "the input is invalid\n");
            Salt_Print(stdout, "testInitRefSalt", s);
            pass = false;
          }
          if (ret == false && secretOk == true && saltOk == true) {
            printf("testInitRefSalt fail: Initialize salt failed but secret "
                   "'%s' and salt '%s' are "
                   "valid, error %s\n",
                   sPtr, saltPtr, errStr);
            pass = false;
          }
          if (ret == true) {
            s->OutputLen = ol;
            s->Iterations = iter;
            ret = Salt_Generate(s, &newPwd);
            if (ret == false) {
              Salt_FreeSalt(s);
            }
            olOk = isValidOutputLen(ol);
            iterOk = isValidNumOfIterations(iter);
            if (ret == false && olOk == true && iterOk == true) {
              printf("testInitRefSalt fail: Initialize salt faild but output "
                     "length %d and "
                     "iterations %d are valid\n",
                     ol, iter);
              pass = false;
            } else if (ret == true && (olOk == false || iterOk == false)) {
              printf("testInitRefSalt fail: Initialize failed: initialize was "
                     "done successfully "
                     "but the input is invalid\n");
              Salt_Print(stdout, "testInitRefSalt", s);
              pass = false;
            }
            if (ret == true) {
              if (NumOfTestsCnt < NUM_OF_TESTS) {
                refRunsSalt[NumOfTestsCnt].S = s;
                refRunsSalt[NumOfTestsCnt].Res = newPwd;
                NumOfTestsCnt++;
              } else {
                snprintf(errStr, sizeof(errStr), "testInitRefSalt: Internal error: Increase the NUM_OF_TESTS (%d) parameter\n", NumOfTestsCnt);
                Utils_Abort(errStr);
              }
            }
            if (pass == false) break;
          }
          if (pass == false) break;
        }
        if (pass == false) break;
      }
      if (clearSalt == true) {
        Utils_Free(saltR);
        // clearSalt = false;
      }
    }
    if (clearS == true) {
      Utils_Free(secretR);
      // clearS = false;
    }
  }
  return pass;
}

// Verify that Different parameters (secret keys, salt, output len, input)
// result with different
// generated password
STATIC bool testSaltParamesChanged() {
  int16_t i = 0, j = 0;
  bool pass = true, equal = true;

  for (i = 0; i < NumOfTestsCnt; i++) {
    for (j = i + 1; j < NumOfTestsCnt; j++) {
      equal = true;
      if (refRunsSalt[i].S->OutputLen != refRunsSalt[j].S->OutputLen) {
        // equal = false;
        continue;
      }
      if (Utils_CharArrayCmp(refRunsSalt[i].Res, refRunsSalt[j].Res) == false) {
        equal = false;
      }
      if (equal == true) {
        printf("testSaltParamesChanged failed: different salt parameters "
               "return the same password: '%s'\n",
               refRunsSalt[i].Res);
        Salt_Print(stdout, "First salt:", refRunsSalt[i].S);
        Salt_Print(stdout, "Second salt:", refRunsSalt[j].S);
        pass = false;
        break;
      }
    }
  }
  return pass;
}

// Verify that the same parameters (secret keys, salt, output len, input,
// digests) result with the
// same generated password
STATIC bool testSaltRepetitation() {
  int16_t i = 0;
  bool pass = true;
  unsigned char *newPwd;

  for (i = 0; i < NumOfTestsCnt; i++) {
    Salt_Generate(refRunsSalt[i].S, &newPwd);
    if (Salt_IsEqual(refRunsSalt[i].S, newPwd) == false) {
      printf("testSaltRepetitation failed: The same salt yield to different "
             "results: error %s\n",
             errStr);
      Salt_Print(stdout, "Salt:", refRunsSalt[i].S);
      printf("calculated password: '%s'\n", newPwd);
      pass = false;
    }
    Utils_Free(newPwd);
  }
  return pass;
}

typedef struct {
  int16_t Iteration;
  int16_t PwdLen;
  char *Password;
} testHashS;

// Results are from http://www.lorem-ipsum.co.uk/hasher.php
STATIC bool testStaticCalculationSalting() {
  int16_t i = 0, j = 0, k = 0, len = 0, saltLen = 0, digestLen = crypto_hash_BYTES + UTILS_STR_LEN_SIZE;
  int16_t cnt = 0, vec[2] = { 16, 1 };
  bool pass = true;
#ifdef MBEDTLS_CRYPTO
  testHashS data[] = { { 1, 64, "a193d7d1ba2253b712d13a0dd27bd7dfddcf04a6c8d904ae7e0e9ba2ced0f8fb" } };
#else
  testHashS data[] = { { 1, 128, "dd0f8983e5a770442a0aca37f62e59ef15988a508bd43ed2e6a9ce0ac94caefe7"
                                 "f25bca6d1ef2d6196ae981737c055900378463cac60769d59b15d0ab0b5dc3"
                                 "0" } };
#endif
  unsigned char digest[digestLen + 1];
  char *testPwd = "ABCD", *testSalt = "A1B2";
  SaltS *s;

  Salt_NewSalt(&s, (unsigned char *)testPwd, (unsigned char *)testSalt);
  s->OutputLen = crypto_hash_BYTES;
  len = sizeof(data) / sizeof(testHashS);

  for (i = 0; i < len; i++) {
    cnt = UTILS_STR_LEN_SIZE;
    for (j = 0; j < data[i].PwdLen; j += 2) {
      if (cnt < digestLen) {
        digest[cnt] = 0;
        for (k = 0; k < 2; k++) {
          if (data[i].Password[j + k] >= 'a' && data[i].Password[j + k] <= 'f')
            digest[cnt] += (data[i].Password[j + k] - 'a' + 10) * vec[k];
          else
            digest[cnt] += (data[i].Password[j + k] - '0') * vec[k];
        }
        cnt++;
      }
    }
    digest[cnt] = 0;
    Utils_SetCharArrayLen(digest, cnt - UTILS_STR_LEN_SIZE);
    s->Iterations = data[i].Iteration;
    if (Salt_IsEqual(s, digest) == false) {
      printf("testStaticCalculationSalting failed: Expected external password "
             "'%s' did not matched "
             "calculated password, error: %s\n",
             data[i].Password, errStr);
      Utils_GetCharArrayLen(s->caSalt, &saltLen, MIN_SALT_LEN, MAX_SALT_LEN);
      printf("Calculated strings: pwd '%s', salt: %s\n", s->caSecret, s->caSalt);
      pass = false;
    }
  }
#ifndef MBED_OS
  FILE *devNull = fopen("/dev/null", "w");
  Salt_Print(devNull, "test print: \n", s);
  fclose(devNull);
#endif
  Salt_FreeSalt(s);
  return pass;
}

STATIC bool testRandomSalt() {
  int16_t i = 0;
  bool ret = false, pass = true;
  unsigned char *newSalt;

  for (i = -10; i < MAX_SALT_LEN + 30; i += 10) {
    ret = getRandomSalt(i, &newSalt);
    if (ret == true && (i < MIN_SALT_LEN || i > MAX_SALT_LEN)) {
      printf("testRandomSalt failed: get random salt: '%s' for ilegal size of: "
             "%d\n",
             newSalt, i);
      pass = false;
    } else if (ret == false && i >= MIN_SALT_LEN && i <= MAX_SALT_LEN) {
      printf("testRandomSalt failed: Generating of random salt for size %d "
             "fail, error: %s\n",
             i, errStr);
      pass = false;
    }
    if (ret == true) Utils_Free(newSalt);
  }
  return pass;
}

// test that the generated password using the same parameters are equal
// test that the generated password using different parameters are not equal
STATIC bool testPwdGeneration() {
  int i = 0;
  bool pass = true;
  unsigned char *pwd[2], *salt[2], *resPwd[4];

  Utils_GenerateCharArray((unsigned char *)DEFAULT_PASSWORD, strlen(DEFAULT_PASSWORD), &(pwd[0]));
  Utils_GenerateCharArray((unsigned char *)"pass1234", 8, &(pwd[1]));
  Utils_GenerateCharArray((unsigned char *)DEFAULT_SALT, strlen(DEFAULT_SALT), &(salt[0]));
  Utils_GenerateCharArray((unsigned char *)"abc", 3, &(salt[1]));
  if (Salt_GenerateCharArraySaltedPassword(pwd[0], salt[0], &(resPwd[0])) == false ||
      Salt_GenerateCharArraySaltedPassword(pwd[0], salt[0], &(resPwd[1])) == false ||
      Salt_GenerateCharArraySaltedPassword(pwd[0], salt[1], &(resPwd[2])) == false ||
      Salt_GenerateCharArraySaltedPassword(pwd[1], salt[0], &(resPwd[3])) == false) {
    printf("testPwdGeneration failed: fanction with valid parameters return false, error: %s\n", errStr);
    pass = false;
  }
  if (Utils_CharArrayCmp(resPwd[0], resPwd[1]) == false) {
    printf("testPwdGeneration failed: pwd1 and pwd2 must be the same\n");
    pass = false;
  }
  if (Utils_CharArrayCmp(resPwd[0], resPwd[2]) == true || Utils_CharArrayCmp(resPwd[0], resPwd[3]) == true) {
    printf("testPwdGeneration failed: pwd1 and pwd3, pwd4 must not be the same\n");
    pass = false;
  }
  if (Salt_GenerateCharArraySaltedPassword(NULL, salt[0], &pwd[0]) == true || Salt_GenerateSaltedPassword(NULL, salt[0], false, 1, &(pwd[0])) == true ||
      Salt_GenerateSaltedPassword(pwd[0], NULL, false, 1, &(pwd[0])) == true) {
    printf("testPwdGeneration failed: fanction with NULL parameters return true\n");
    pass = false;
  }
  for (i = 0; i < 2; i++) {
    Utils_Free(pwd[i]);
    Utils_Free(salt[i]);
    Utils_Free(resPwd[i]);
    Utils_Free(resPwd[i + 2]);
  }
  return pass;
}


STATIC void freeRef() {
  int16_t i = 0;

  for (i = 0; i < NumOfTestsCnt; i++) {
    Salt_FreeSalt(refRunsSalt[i].S);
    Utils_Free(refRunsSalt[i].Res);
  }
}

#ifdef MBED_OS
int16_t testSalt()
#else
int main()
#endif
{
  bool pass = true;
  int16_t i = 0, len = 0;
  char *res = NULL;
  Salt_TestMode = true;

  Utils_TestFuncS callFunc[] = { { "testInitRefSalt", testInitRefSalt },
                                 { "testSaltParamesChanged", testSaltParamesChanged },
                                 { "testSaltRepetitation", testSaltRepetitation },
                                 { "testStaticCalculationSalting", testStaticCalculationSalting },
                                 { "testRandomSalt", testRandomSalt },
                                 { "testPwdGeneration", testPwdGeneration } };

  len = sizeof(callFunc) / sizeof(Utils_TestFuncS);
  for (i = 0; i < len; i++) {
    if ((callFunc[i]).testFunc() == false) {
      res = "fail";
      pass = false;
    } else
      res = "pass";
    printf("Test %s:'%s' %s\n", __FILE__, callFunc[i].name, res);
  }
  freeRef();
  return pass;
}
