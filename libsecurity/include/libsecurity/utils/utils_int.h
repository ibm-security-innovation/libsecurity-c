#pragma once

#include "utils.h"

#define NAME_STR "Name"
#define PREFIX_STR "Store prefix"

#define MAX_IP_STR_LEN 16

#define EXTRA_CHARS "!@#%^&()-_.,"

#define PWD_MAX_COUNTERS	4 // must be the length of the CHAR_TYPE
typedef enum {UpperCaseIdx=0, LowerCaseIdx, DigitIdx, OtherIdx} PwdCharType;
