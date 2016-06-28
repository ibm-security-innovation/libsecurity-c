#include "mbed-drivers/mbed.h"

#include "libsecurity/utils/utils.h"

extern "C" {
	int testStorage();
	int testUtils();
	int testAcl();
	int testAccounts();
	int testEntity();
	int testPassword();
	int testOtp();
	int testSalt();
	int iotClient();	
}

typedef struct {
  const char *name;
  int (*testFunc)(void);
}testFuncS;

unsigned long mbedtls_timing_hardclock( void )
{
    static int dwt_started = 0;

    if( dwt_started == 0 )
    {
        CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
        DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    }

    return( DWT->CYCCNT );
}

class TestLibsecurity {
public:
    TestLibsecurity() {}

	void runTests(void) {
		const char *res=NULL;
		testFuncS callFunc[] = {
			{"testAccounts", testAccounts},
			{"testAcl", testAcl},
			{"testEntity", testEntity},
			{"testOtp", testOtp},
			{"testPassword", testPassword},
			{"testSalt", testSalt},
			{"testStorage", testStorage},
			{"testUtils", testUtils},
			{"iotClient", iotClient}
		};

		bool pass = true;
		int len = sizeof(callFunc) / sizeof (testFuncS);
		for (int i=0 ; i<len ; i++) {
			if ((callFunc[i]).testFunc() == false) {
				res = "fail";
				pass = false;
			}else {
				res = "pass";
			}
		    printf("Run '%s' %s\n", callFunc[i].name, res);
		}
		if (pass == false)
			res = "fail";
		else
			res = "pass";
		printf("OK done, test %s\n", res);
	}
	protected:
};

void app_start(int argc, char *argv[]) {
    (void) argc;
    (void) argv;

   	get_stdio_serial().baud(115200);
	printf("\n\n\n\n\nstart\n");

	TestLibsecurity *tl = new TestLibsecurity();
	mbed::util::FunctionPointer0<void> fp(tl, &TestLibsecurity::runTests);
    minar::Scheduler::postCallback(fp.bind());
}
