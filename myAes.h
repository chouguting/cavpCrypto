#pragma once


extern const int AES_MODE_ECB;
extern const int AES_MODE_CBC;
extern const int AES_MODE_CFB8;
extern const int AES_MODE_CFB128;
extern const int AES_MODE_CTR;

extern const int AES_KEY_SIZE_128;
extern const int AES_KEY_SIZE_192;
extern const int AES_KEY_SIZE_256;

int aesEncrypt(int mode, int keySize, char* keyString, char* plaintextString, char* initialVectorString, char* ciphertextString);

int aesDecrypt(int mode, int keySize, char* keyString, char* ciphertextString, char* initialVectorString, char* plaintextString);

void aesEcbMCTEncrypt(int mode, int keySize, char* plaintextString, char* keyString);
void aesEcbMCTDecrypt(int mode, int keySize, char* ciphertextString, char* keyString);