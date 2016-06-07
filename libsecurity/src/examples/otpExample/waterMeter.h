#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "libsecurity/otp/otpUser.h"

bool WaterMeter_InitWaterMeter(const unsigned char *secret);
void WaterMeter_Clean(void);
bool WaterMeter_ReadWaterMeterValue(const char *otpVal, OtpType type, int32_t *val);
