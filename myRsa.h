#pragma once
#include <tomcrypt.h>

rsa_key rsaKeyPair();
char* rsaSignMessage_pkcs1_v1_5(const char* message, const int hashAlgo);
char* rsaSignMessage_pss(const char* message, const int hashAlgo);
int rsaVerifyMessage_pkcs1_v1_5(const char* message, const char* signature, const int hashAlgo, rsa_key* key);
int rsaVerifyMessage_pss(const char* message, const char* signature, const int hashAlgo, rsa_key* key);