#include "waterMeter.h"

typedef struct{
  OtpUserS *otpData;
}WaterMeter;

static WaterMeter waterMeter;

bool WaterMeter_InitWaterMeter(const unsigned char *secret) {
  if (OtpUser_NewSimpleUser(&(waterMeter.otpData), secret) == false) {
    printf("WaterMeter_InitWaterMeter failed, Can't create OTP, error: %s\n", errStr);
    return false;
  }
  return true;
}

void WaterMeter_Clean(void) {
	OtpUser_FreeUser(waterMeter.otpData);
}

static int32_t getWaterMeterValue(void) {
  static int32_t value = 100;

  value += 10;
  return value;
}

bool WaterMeter_ReadWaterMeterValue(const char *otpVal, OtpType type, int32_t *val) {
  if (OtpUser_VerifyCode(waterMeter.otpData, otpVal, type) == false)
    return false;
  *val = getWaterMeterValue();
  return true;
}

