#pragma once

#define	ROOT_USER_NAME		"root"
#define	ALL_ACL_NAME "All" // the same as in Linux

#define	NUM_OF_PRIVILEGE			3
#define	SUPER_USER_PERMISSION_STR		"Super-user"
#define	ADMIN_PERMISSION_STR			"Admin"
#define	USER_PERMISSION_STR  			"User"

typedef enum {SUPER_USER_PERMISSION, ADMIN_PERMISSION, USER_PERMISSION} PrivilegeType;

#define	ACL_PROPERTY_NAME 			"acl_"
#define	OTP_PROPERTY_NAME			"otp_"
#define	PWD_PROPERTY_NAME 			"pwd_"
#define	AM_PROPERTY_NAME 			"am_"

#define MIN_PREFIX_LEN	1
#define MAX_PREFIX_LEN	40

#define LIB_NAME	"Libsecurity-c"

#ifdef STATIC_F // for testing mode
#define STATIC
#else
#define STATIC static
#endif

