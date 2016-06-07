# libsecurityc-c

## Overview:

### The goals of libsecurity are:
Secure "things" that connect to the internet by providing a set of security libraries/services that fulfill the following requirements:
1.  Complete (from a security point of view)
2.  Can be easily integrated with existing IoTs' software.
3.  Optimized for the IoTs' run time environment

### Language
- Implemented in c/c++

## Provided Libraries:
  - Account Management services:  User privileges and password management
  - Secure storage services: Persistency mechanism that uses Encryption (AES) of key-value pairs within a signed file
  - Entity management services to handle 3 types of entities: User, Group and Resource.
  - Password services:  encryption, salting, reset, time expiration, Throttling mechanism
  - Access Control List (ACL) services when access rights may be defined for resource entity. The  implementation should allow flexible types of access to resources (not limited to READ/WRITE/EXECUTE).
  - One Time Password (OTP) services as defined by RFCs 4226 (HOTP), 6238 (TOTP)

## Installation

### Prerequisites
- For MBED-OS devices (K64F) you will need to install yotta, see http://yottadocs.mbed.com/#installing-on-linux
- g++ compiler: you need at least version 4.8 (the other option is to remove the -std=c++11 flag from CPPFLAGS in 
libsecurity-c/libsecurity/src/build/common.mk)
- Valgrind: The package testing runs by default using valgrind. In order to override the default and run it without valgrind, enter to the Linux prompt: export PURE=1

### Quick Start
- Get libsecurity-c and its dependencies: `git clone github.com/ibm-security-innovation/libsecurity-c/...`
- make deps
- make

#### MBED-OS Quick Start
- Get libsecurity-c and its dependencies: `git clone github.com/ibm-security-innovation/libsecurity-c/...`
- cd mbed/K64F/libsecurity
- yotta target frdm-k64f-gcc
- build.sh
- yotta build
- copy build/frdm-k64f-gcc/source/libsecurity.bin to your K64F device

### Setup

#### Compilation flags
There are two compilation flags that must be set based on the platform for which the library is compiled for. These are:
- TARGET - may be LINUX_OS or MBED_OS based on the OS. 
- CRYPTO_TYPE - may be NaCl_CRYPTO or MBEDTLS_CRYPTO.

These flags are set in  libsecurity-c/libsecurity/src/build/common.mk in the following way:
- For Linux with NaCl cryptographic library: 
    - TARGET=-DLINUX_OS
    - CRYPTO_TYPE=-NaCl_CRYPTO
- For Linux with mbed TLS cryptographic library, when the CPU is not Intel or AMD (e.g. Beaglebone Black device):
    - TARGET=-DLINUX_OS
    - CRYPTO_TYPE=-MBEDTLS_CRYPTO
- For MBED OS devices when the CPU is ARM (e.g. K64F device):
    - TARGET=-DMBED_OS
    - CRYPTO_TYPE=-MBEDTLS_CRYPTO

#### Optional flags for different purposes:
To run a full test, in the libsecurity-c/libsecurity/src/build directory:
- Execute: run_all.sh to will run all the tests of all the packages
- Execute: run_all.sh CHECK to run a test of all the libsecurity followed by a check of the code formating and cleanleaness. Note that in order to perform the formatting check clang must be installed and the cleanness check uses scan-build
- The results of the tests will be stored in the libsecurity-c/libsecurity/src/build/res directory when the res file will hold the summary of the tests and the full_res file will hold all the details
- Each library package has its own set of tests stored in a subdirectory named after the package under the test directory. The package testing runs by default using valgrind. In order to override the default and run it without valgrind, enter to the Linux prompt: export PURE=1
- To check the overall testing coverage and the coverage per package set the environment variable by enter to the Linux prompt: export COV=1
- Compilations can be done using GCC, GCC with optimization or CLANG. To switch between those options, set in the Linux prompt the COMPILER variable either to "GCC_C" (gcc with debug), "GCC_O" (gcc with optimization) or "CLANG" (the clang compiler). The default is "GCC_C" GCC with debug. e.g. export COMPILER="CLANG"

### Usage examples:
In order to exemplify how to use the libsecurity-c library, the library includes the following usage examples under the libsecurity-c/libsecurity/src/examples directory:

##### Acl example:
This example shows how to set ACL permissions of a resource, in this case a smart TV, for users and groups of users. The example shows all the options to set users' and groups' permissions, including permissions for:
  - A specific user
  - A group of users
  - All users
  - This example also demonstrates the way these permissions affect each user
  - Notes:
    - Permissions are strings, and are not limited to a specific set of values
    - The data is saved in a secure way to a file and is later used whenever a user attempts to access the resource

##### Otp example: 
This example shows how to use One Time Password (OTP).
In this example a smart water meter returns its current value only to users with the correct one time password. 
  - This example starts with the generation of two users (a technician and a customer) and a resource (a water meter).
  - Next, an ACL is added to the water meter in which only the technician is allowed to read the water meter value.
  - Each time the technician has to read the water meter, his system calculates the next OTP and uses it when attempting to read the water meter value. If the technician's OTP matches the one calculated internally it returns the current value. This example shows how to use HOTP (counter based OTP) as well as TOTP (time based OTP).
  - Note: In order to use the time based OTP there should be a delay of OTP time base window (default is 30 sec) between consecutive call attempts. This is done in order to protect against replay attacks.

##### Secure storage example: 
This example shows how to store a wifi password to a secure storage. The rationale behind this example is that saving a password as clear text may result with the password being stolen putting your home or work wifi under threat of being abused.
  - As part of this example each key and password are stored after encryption using AES algorithm.
  - Before storing the secure storage to a file, it is signed to ensure that it won't be compromised

##### Full example:
This example shows how to use each and every package of the libsecurity-c library.
##### App example:
This example shows a demo application that sends MULE or log messages to server.
- The messages can be sent in one of two forms:
  - Clear text to Linux rsyslog
  - Encrypted message using DTLS (over UDP) to the goldy server (in this case you will need to download and run goldy application on a Linux machine, see https://github.com/ibm-security-innovation/goldy)
- Note: The IoTClient application can be executed on a machine that is different than the one of the goldy client. If this is the case, the relevant ports on the iptables must be opened.

# License
(c) Copyright IBM Corp. 2010, 2015
This project is licensed under the Apache License 2.0. See the LICENSE file for more info.
Authors: Ravid Sagy, Dov Murik, Shmulik Regev

## Contribution

Contributions to the project are welcomed.  It is required however to provide
alongside the pull request one of the contribution forms (CLA) that are a part
of the project.  If the contributor is operating in his individual or personal
capacity, then he/she is to use the [individual CLA](./CLA-Individual.txt); if
operating in his/her role at a company or entity, then he/she must use the
[corporate CLA](CLA-Corporate.txt).

## Dependencies & 3rd Party
[NaCl](https://nacl.cr.yp.to/) is used for encryption when compiled for Linux.

[mbedTLS](https://tls.mbed.org/) is used for encryption when compiled for mbedOS.

[hashtab](http://burtleburtle.net/bob/hash/hashtab.html) is used.


# libsecurity-c architecture and high level design document
## Overview:
The purpose of libsecurity-c is to provide an efficient solution for securing Internet Of Things end devices and gateways. This solution does not require any deep understanding of security and thus relieves IoT developers from the need to learn and understand the different aspects of security (e.g. how to create and maintain secure-storage, when to use One Time Password etc.).

Libsecurity-c implementations targeted to small capable IoT platforms with limited resources (e.g. ARM Cortex M). 

## Architecture and High level design:
The following diagram details the layers of libsecurity :

- The encryption layer is the lowest one (where either NaCl encryption or MBEDTLS encryption library are used).
- The second layer, Secure Storage, implements secure storage for persistency. The secure storage is based on encrypted key value pairs stored in signed files to guarantee that the data is not altered or corrupted (more details will be presented later)
- The next layers are designed as entity centric, where entities must have a name and may have a list of associated properties and a list of members (see more details and example below)

### Library structure:
- Each package includes a code directory and a testing directory (to run the tests, execute run.sh from the relevant testing directory)
- Examples directory: 
   - Each of the main packages has its own usage-example directory that shows in detail how to use that package
   - The appExample directory - an example of a full (tiny) application that shows a full IoTClient application that sends log and mule messages to an external server using DTLS and a predefined protocol

### Major Data and Property Structures:

#### Secure Storage
- Allows maintaining data persistently and securely. The implementation of the secure storage is based on encrypted key value pairs stored in signed files to guarantee that the data is not altered or corrupted.
- Both the key and the value are encrypted when added to the storage using an Advanced Encryption Standard (AES) algorithm.
- Each time a new secure storage is generated, a secret supplied by the user accompanies it and is used in all HMAC and AES calculations related to that storage.
In order to make it difficult for a third party to decipher or use the stored data we ensure that multiple independent encryptions of the same data (e.g. a block with the same piece of plain text) with the same key have different results. This is achieved by implementing the Cipher Block Chaining (CBC) mode.
- In order to implement a time efficient secure storage with keys (i.e. identify keys that are already stored without decrypting the entire storage, and when such a key is identified replacing its value) a two step mechanism is used. The first time a key is introduced, a new IV is drawn, the key is 'HMAC'ed with the secret and is stored with the IV as the value (1st step). Than the original key is encrypted with the drawn IV and stored again, this time with the (encrypted with its own random IV) value (2nd step).  The next time that same key is stored, the algorithm, identifies that it already exists in the storage, pulls out the random IV (stored in the 1st step), finds the 2nd step storage of that key and replaces its value with the new (encrypted) one.
- In order to guarantee that the data is not altered or corrupted the storage is signed using HMAC. The signature is added to the secure storage, when the storage is loaded, HMAC is calculated and compared with the stored signature to verify that the file is genuine.

- Entity structure:
    - There are three types of entities: User, Group and resource
        - Users have a name and a list of properties
        - Groups have a name, list of members associated with it (each member is a name of an existing entity) and a list of properties
        - Resources have a name and a list of properties
        - There is a special group entity, that is not defined explicitly, with the name "All". This entity is used in the ACL when the resource has permission properties that applies to all the entities in the system

- Properties:
    - ACL property structure:
        - An ACL has a list of entries. Each ACL entry consists of the following fields:
            - An entry name (obligatory, must be the name of an entity from the entity list)
            - List of permissions (optional)

        - Example:
        - Consider the following entity list:
          - Name: User1
          - Name: User2
          - Name: User3
          - Name: IBM, members: User2, User3
          - Name: All (reserved token)
          - Name: Disk, properties: ACL:
          - ACL →
              - Name: User1, properties: “can write”, “can take”
              - Name: IBM, properties: “can read”
              - Name: All, Properties: “can execute”
          - In this example:
          1. The user-entity named User1 has the following permissions with relation to the resource-entity Disk: “can write”, “can take” and “can execute” (via All)
          2. The group-entity named IBM has the following permissions with relation to the resource-entity Disk: “can read” and “can execute” (via All)
          3. The user-entity named User2 has the following permissions with relation to the resource-entity Disk: “can read” (via IBM) and “can execute” (via All)

          - Note: if User1 is removed from the Entity list and then re added, the only permission it will initially have is “execute” (via All). This is because a removed entity cannot be re-added, but a new entity with its name can be created. In this case, the new Entity User1 may be of a different user than the one that originally received the permissions.

    - The OTP property:
        - According to Wikipedia: A One Time Password (OTP) is a password that is valid for only one login session or transaction (and may be limited for a specific time period). The most important advantage that is addressed by OTPs is that, in contrast to static passwords, they are not vulnerable to replay attacks. A second major advantage is that a user who uses the same (or similar) password for multiple systems, is not made vulnerable on all of them, if the password for one of these is gained by an attacker.
Libsecurity implements the 2 possible OTP implementations: A time based one time password algorithm (TOTP) and HMAC-based one time password algorithm (HOTP). Our OTP implementation is based on RFC 2289 for OTP in general, RFC 4226 for HOTP, and RFC 6238 for TOTP.
        - The OTP implementation has three layers:
            - The base layer includes the secret, the digest (e.g. SHA256, SHA1) and the number of digits in the result.
            - The second layer is the counting mechanism which is time based for TOTP and counter based for HOTP.
            - The topmost layer includes the policy of handing unsuccessful authentication attempts. This includes blocking and throttling. The blocking mechanism allows blocking users for a given duration (or until a manual unblock) after they pass a threshold which a limit for the number of allowed consecutive unsuccessful authentication attempts. The throttling mechanism controls the delay between the authentication request and the response. This delay is increased as the number of consecutive unsuccessful attempts grows to avoid brute force password attacks. This layer also includes a time window for avoiding clock drifting errors when TOTPs are used.
