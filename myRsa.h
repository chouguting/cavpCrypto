#pragma once
#include <tomcrypt.h>

rsa_key rsaKeyPair();
char* rsaSignMessage_pkcs1_v1_5(const char* message, const int hashAlgo, unsigned long* sig_len);
