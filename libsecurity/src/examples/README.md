# libsecurityc-c Examples
## - Storage Example:
    This example shows how to store a wifi password to a secure storage.
    The rational behind this example is that saving a password as clear text may result with the password being stolen putting your home or work wifi under threat of being abused
    Through this example each key and password are stored after encryption using AES algorithm
    Before storing the secure storage to a file, it is signed to ensure that it won't be compromised

## - ACL Example:
    This example shows how to set ACL permissions of a resource, in this case a smart TV, for users and groups of users.
    The first step is adding the groups (in this case, a single group) and users to the entity list.
    The second step is adding users to the groups they belong to.
    The third step is setting the users' and groups' permissions, when permissions can be set for:
    1. a specific user
    2. a group of users
    3. all users
    This example, includes all 3 types of permissions and demonstrates the way affect each user
##### Notes:
  - Permissions are strings, and are not limited to a specific set of values.
  - The data is saved in a secure way to a file and is later used whenever a user attepts to access the resource

## - One Time Password Example:
    This example shows how to use One Time Password (OTP).
    In this example a samrt water meter returns its curent value only to users with the correct one time password.
    This example starts with the generation of two users (a technician and a customer) and a resource (a water meter).
    Next, an ACL is added to the water meter in which only the technician is allowed to read the value of the water meter value.
    Each time the technician has to read the water meter, it calculates the next OTP and uses it when attempting to read the water meter value. If the technition's OTP matches the one calculated internaly it returns the curent value. This example shows how to use HOTP (counter based OTP) as well as TOTP (time base OTP).
**Note:** In order to use the time based OTP there should be a delay of OTP time base window (default is 30 sec) between consecutive call attempts. This is done in order to protect against replay attacks.

## - Full Example:
  This example shows the usage of the following features:
### 1. EntityManager: 
    1.1 How to add/Remove users/groups to the entity manager.
    1.2 How to add resources to the entity manager.
### 2. ACL: 
    2.1 How to set permissions for users/groups/all in relation to a resource 
    2.2 How to check if a specific user has a permission for the given resource
    2.3 How to get all the permissions set to a given resource
    2.4 How to get all the entities that have a given permission for a given resource
### 3. OTP: 
    3.1 How to add OTP property to a given resource.
    3.2 How to calculate and verify that an OTP matches the expected OTP (both counter based OTP: HOTP and time based OTP TOTP)
### 4. Password:
    4.1 How to add a password property to a given resource.
    4.2 How to verify that a password matches the expected password.
    4.3 How to update a password and verify that the old password doesn't match.
    4.4 How to generate a true random password that is strong enough.
###  5. Storage:
    5.1 How to add a key value to an encrypted storage.
    5.2 How to retrieve a value for a given key.
    5.3 How to store and load an encrypted storage.
**Note:** Before storing the secure storage to a file, it is signed to ensure that it won't be compromised
