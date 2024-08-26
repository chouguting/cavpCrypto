#include <tomcrypt.h>
#include <tommath.h>
#include "stdio.h"
#include "string.h"
#include "utils.h"

const int AES_MODE_ECB = 1;
const int AES_MODE_CBC = 2;
const int AES_MODE_CFB8 = 3;
const int AES_MODE_CFB128 = 4;
const int AES_MODE_CTR = 5;

const int AES_KEY_SIZE_128 = 16;
const int AES_KEY_SIZE_192 = 24;
const int AES_KEY_SIZE_256 = 32;


int aesEncrypt(int mode, int keySize, char* keyString, char* plaintextString, char* initialVectorString, char* ciphertextString) {
	//unsigned char key[16] = { 0 }; // 128 bits key
    //unsigned char plaintext[16] = "hello world"; 
    //unsigned char ciphertext[16]; 
	int plaintextStringLength = strlen(plaintextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initialVectorString);

	unsigned char* plaintextByte = malloc(plaintextStringLength / 2);
	unsigned char* keyByte = malloc(keyStringLength / 2);
	unsigned char* initialVectorByte = malloc(initialVectorStringLength / 2);
	unsigned char* ciphertextByte = malloc(plaintextStringLength / 2); // 輸出的密文(長度和明文一樣)

	int plaintextByteLength;
	int keyByteLength;
	int initialVectorByteLength;
	int ciphertextByteLength = plaintextStringLength / 2;

	hex_to_bytes(plaintextString, plaintextByte, &plaintextByteLength);
	hex_to_bytes(keyString, keyByte, &keyByteLength);
	hex_to_bytes(initialVectorString, initialVectorByte, &initialVectorByteLength);

    
    int err;

	//檢查keyLength
	switch (keySize)
	{
	case 16: //AES-128 (16byte=128bit)
		if (keyByteLength != 16) {
			printf("key length error\n");
			return -1;
		}
		break;
	case 24: //AES-192 (24byte=192bit)
		if (keyByteLength != 24) {
			printf("key length error\n");
			return -1;
		}
		break;
	case 32: //AES-256 (32byte=256bit)
		if (keyByteLength != 32) {
			printf("key length error\n");
			return -1;
		}
		break;
	default:
		printf("unknown key size\n");
		return -1;
		break;

	}

	// 初始化AES
    if (register_cipher(&aes_desc) == -1) {
        printf("register AES error\n");
        return -1;
    }

	//不同模式的加密
	switch (mode)
	{
	case 1: //ECB
		symmetric_ECB ecb;
		// 初始化key
		if ((err = ecb_start(find_cipher("aes"), keyByte, keyByteLength, 0, &ecb)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		// 加密
		if ((err = ecb_encrypt(plaintextByte, ciphertextByte, plaintextByteLength, &ecb)) != CRYPT_OK) {
			printf("encryption error: %s\n", error_to_string(err));
			return -1;
		}

		// 結束AES
		if ((err = ecb_done(&ecb)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;
	case 2: // CBC

		symmetric_CBC cbc;

		// 初始化key
		if ((err = cbc_start(find_cipher("aes"),initialVectorByte, keyByte, keyByteLength, 0, &cbc)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		// 加密
		if ((err = cbc_encrypt(plaintextByte, ciphertextByte, plaintextByteLength, &cbc)) != CRYPT_OK) {
			printf("encryption error: %s\n", error_to_string(err));
			return -1;
		}

		// 結束AES
		if ((err = cbc_done(&cbc)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;
	case 3: //CFB8
		symmetric_ECB cfb8;
		unsigned char initialVectorBufferByte[16]; //16byte的buffer
		unsigned char middleResultByte[16]; //16byte的buffer
		
		memcpy(initialVectorBufferByte, initialVectorByte, 16); //複製initialVectorByte到initialVectorBufferByte
		
		// 初始化key
		if ((err = ecb_start(find_cipher("aes"), keyByte, keyByteLength, 0, &cfb8)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		//逐個byte加密
		for (int i = 0; i < plaintextByteLength; i++) {
			//加密
			if ((err = ecb_encrypt(initialVectorBufferByte, middleResultByte, 16, &cfb8)) != CRYPT_OK) {
				printf("encryption error: %s\n", error_to_string(err));
				return -1;
			}
			//把middleResultBufferByte的第一個byte存到ciphertextByte
			ciphertextByte[i] = middleResultByte[0] ^ plaintextByte[i];
			
			// initialVector = { initialVector[1], initialVector[2], ..., initialVector[15], ciphertextByte[i] }
			//先左移一個byte
			for (int j = 0; j < 15; j++) {
				initialVectorBufferByte[j] = initialVectorBufferByte[j + 1];
			}
			//把ciphertextByte[i]存到最後一個byte
			initialVectorBufferByte[15] = ciphertextByte[i];

		}

		// 結束AES
		if ((err = ecb_done(&cfb8)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;

	case 4: //CFB128
		symmetric_CFB cfb128;
		// 初始化key
		if ((err = cfb_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, &cfb128)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		// 加密
		if ((err = cfb_encrypt(plaintextByte, ciphertextByte, plaintextByteLength, &cfb128)) != CRYPT_OK) {
			printf("encryption error: %s\n", error_to_string(err));
			return -1;
		}

		// 結束AES
		if ((err = cfb_done(&cfb128)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;

		//TODO: 維修CTR模式
	case 5: //CTR
		symmetric_CTR ctr;
		ctr.padlen = 0; //不使用padding
		// 初始化key
		if ((err = ctr_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, CTR_COUNTER_LITTLE_ENDIAN , &ctr)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		// 加密
		if ((err = ctr_encrypt(plaintextByte, ciphertextByte, plaintextByteLength, &ctr)) != CRYPT_OK) {
			printf("encryption error: %s\n", error_to_string(err));
			return -1;
		}

		// 結束AES
		if ((err = ctr_done(&ctr)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;


	default:
		printf("mode error\n");
		return -1;
		break;
	}

	

	// 輸出密文
	bytes_to_hex(ciphertextByte, ciphertextByteLength, ciphertextString);
	//printf("ciphertext: %s\n", ciphertextString);
    
	//清理
	free(plaintextByte);
	free(keyByte);
	free(initialVectorByte);
	free(ciphertextByte);

    return 0;
}


int aesDecrypt(int mode, int keySize, char* keyString, char* ciphertextString, char* initialVectorString, char* plaintextString) {
	

	int ciphertextStringLength = strlen(ciphertextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initialVectorString);

	
	unsigned char* keyByte = malloc(keyStringLength / 2);
	unsigned char* initialVectorByte = malloc(initialVectorStringLength / 2);
	unsigned char* ciphertextByte = malloc(ciphertextStringLength / 2);
	unsigned char* plaintextByte = malloc(ciphertextStringLength / 2); // 輸出的明文(長度和密文一樣)

	int plaintextByteLength = ciphertextStringLength / 2;
	int keyByteLength;
	int initialVectorByteLength;
	int ciphertextByteLength;

	hex_to_bytes(ciphertextString, ciphertextByte, &ciphertextByteLength);
	hex_to_bytes(keyString, keyByte, &keyByteLength);
	hex_to_bytes(initialVectorString, initialVectorByte, &initialVectorByteLength);


	int err;

	//檢查keyLength
	switch (keySize)
	{
	case 16: //AES-128 (16byte=128bit)
		if (keyByteLength != 16) {
			printf("key length error\n");
			return -1;
		}
		break;
	case 24: //AES-192 (24byte=192bit)
		if (keyByteLength != 24) {
			printf("key length error\n");
			return -1;
		}
		break;
	case 32: //AES-256 (32byte=256bit)
		if (keyByteLength != 32) {
			printf("key length error\n");
			return -1;
		}
		break;
	default:
		printf("unknown key size\n");
		return -1;
		break;

	}

	// 初始化AES
	if (register_cipher(&aes_desc) == -1) {
		printf("register AES error\n");
		return -1;
	}

	//不同模式的解密
	switch (mode)
	{
	case 1: //ECB
		symmetric_ECB ecb;
		// 初始化key
		if ((err = ecb_start(find_cipher("aes"), keyByte, keyByteLength, 0, &ecb)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		// 解密
		if ((err = ecb_decrypt(ciphertextByte, plaintextByte, ciphertextByteLength, &ecb)) != CRYPT_OK) {
			printf("encryption error: %s\n", error_to_string(err));
			return -1;
		}

		// 結束AES
		if ((err = ecb_done(&ecb)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;
	case 2: // CBC

		symmetric_CBC cbc;

		// 初始化key
		if ((err = cbc_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, &cbc)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		// 解密
		if ((err = cbc_decrypt(ciphertextByte, plaintextByte, ciphertextByteLength, &cbc)) != CRYPT_OK) {
			printf("encryption error: %s\n", error_to_string(err));
			return -1;
		}

		// 結束AES
		if ((err = cbc_done(&cbc)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;
	case 3: //CFB8
		symmetric_ECB cfb8;
		unsigned char initialVectorBufferByte[16]; //16byte的buffer
		unsigned char middleResultByte[16]; //16byte的buffer

		memcpy(initialVectorBufferByte, initialVectorByte, 16); //複製initialVectorByte到initialVectorBufferByte

		// 初始化key
		if ((err = ecb_start(find_cipher("aes"), keyByte, keyByteLength, 0, &cfb8)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		//逐個byte解密
		for (int i = 0; i < ciphertextByteLength; i++) {
			//解密
			if ((err = ecb_encrypt(initialVectorBufferByte, middleResultByte, 16, &cfb8)) != CRYPT_OK) {
				printf("encryption error: %s\n", error_to_string(err));
				return -1;
			}
			//把middleResultBufferByte的第一個byte存到ciphertextByte
			plaintextByte[i] = middleResultByte[0] ^ ciphertextByte[i];

			// initialVectorBuffer = { initialVector[1], initialVector[2], ..., initialVector[15], ciphertextByte[i] }
			//先左移一個byte
			for (int j = 0; j < 15; j++) {
				initialVectorBufferByte[j] = initialVectorBufferByte[j + 1];
			}
			//把ciphertextByte[i]存到最後一個byte
			initialVectorBufferByte[15] = ciphertextByte[i];

		}

		// 結束AES
		if ((err = ecb_done(&cfb8)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;
	case 4: //CFB128
		symmetric_CFB cfb;
		// 初始化key
		if ((err = cfb_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, &cfb)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		// 解密
		if ((err = cfb_decrypt(ciphertextByte, plaintextByte, ciphertextByteLength, &cfb)) != CRYPT_OK) {
			printf("encryption error: %s\n", error_to_string(err));
			return -1;
		}

		// 結束AES
		if ((err = cfb_done(&cfb)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;
		//TODO: 維修CTR模式
	case 5: //CTR
		symmetric_CTR ctr;
		// 初始化key
		if ((err = ctr_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
			printf("initialize key error: %s\n", error_to_string(err));
			return -1;
		}

		// 解密
		if ((err = ctr_decrypt(ciphertextByte, plaintextByte, ciphertextByteLength, &ctr)) != CRYPT_OK) {
			printf("encryption error: %s\n", error_to_string(err));
			return -1;
		}

		// 結束AES
		if ((err = ctr_done(&ctr)) != CRYPT_OK) {
			printf("cleaning error: %s\n", error_to_string(err));
			return -1;
		}
		break;


	default:
		printf("mode error\n");
		return -1;
		break;
	}



	// 輸出明文
	bytes_to_hex(plaintextByte, plaintextByteLength, plaintextString);
	//printf("ciphertext: %s\n", ciphertextString);

	//清理
	free(plaintextByte);
	free(keyByte);
	free(initialVectorByte);
	free(ciphertextByte);

	return 0;
}



//Monte Carlo Test: ECB
void aesEcbMCTEncrypt(int keySize, char * plaintextString, char * keyString) {
	int plaintextStringLength = strlen(plaintextString);
	int keyStringLength = strlen(keyString);

	char* lastKeyString = malloc(keyStringLength+1);
	char* lastPlaintextString = malloc(plaintextStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength+1,keyString);
	strcpy_s(lastPlaintextString, plaintextStringLength + 1,plaintextString);

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("plaintext: %s\n", lastPlaintextString);

		char* currentCiphertextString = malloc(plaintextStringLength + 1);
		strcpy_s(currentCiphertextString, plaintextStringLength + 1, lastPlaintextString);
		char* lastCiphertextString = malloc(plaintextStringLength + 1);
		for (int j = 0; j < 1000; j++) {
			strcpy_s(lastCiphertextString, plaintextStringLength+1,currentCiphertextString);
			aesEncrypt(AES_MODE_ECB, keySize, lastKeyString, lastPlaintextString, "", currentCiphertextString);
			strcpy_s(lastPlaintextString, plaintextStringLength + 1, currentCiphertextString);
		}
		printf("ciphertext: %s\n", currentCiphertextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			xor_strings(nextKeyString, lastKeyString, currentCiphertextString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//one char in a hex string is 4 bits, in MCT test ciphertext is 128 bits(32 chars)
			//so to get the last 64 bits of the last ciphertext, we can just point to the 17th char
			char* last64bitsOfLastCiphertextString = lastCiphertextString + 16;
			strcpy_s(concattedString, keyStringLength + 1,last64bitsOfLastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1 ,currentCiphertextString); //concatenate the last 64 bits of the last ciphertext and the current ciphertext (64+128=192 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1,nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			strcpy_s(concattedString, keyStringLength + 1,lastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1,currentCiphertextString); //concatenate the last ciphertext and the current ciphertext (256 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1,nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastPlaintextString, plaintextStringLength + 1, currentCiphertextString);
		free(currentCiphertextString);
	}
	//清理
	free(lastKeyString);
	free(lastPlaintextString);
}



void aesEcbMCTDecrypt(int keySize, char* ciphertextString, char* keyString) {
	int ciphertextStringLength = strlen(ciphertextString);
	int keyStringLength = strlen(keyString);

	char* lastKeyString = malloc(keyStringLength + 1);
	char* lastCiphertextString = malloc(ciphertextStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength + 1, keyString);
	strcpy_s(lastCiphertextString, ciphertextStringLength + 1, ciphertextString);

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("ciphertext: %s\n", lastCiphertextString);

		char* currentPlaintextString = malloc(ciphertextStringLength + 1);
		strcpy_s(currentPlaintextString, ciphertextStringLength + 1, lastCiphertextString);
		char* lastPlaintextString = malloc(ciphertextStringLength + 1);
		for (int j = 0; j < 1000; j++) {
			strcpy_s(lastPlaintextString, ciphertextStringLength + 1, currentPlaintextString);
			aesDecrypt(AES_MODE_ECB, keySize, lastKeyString, lastCiphertextString, "", currentPlaintextString);
			strcpy_s(lastCiphertextString, ciphertextStringLength + 1, currentPlaintextString);
		}
		printf("plaintext: %s\n", currentPlaintextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			xor_strings(nextKeyString, lastKeyString, currentPlaintextString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//one char in a hex string is 4 bits, in MCT test ciphertext is 128 bits(32 chars)
			//so to get the last 64 bits of the last ciphertext, we can just point to the 17th char
			char* last64bitsOfLastCiphertextString = lastPlaintextString + 16;
			strcpy_s(concattedString, keyStringLength + 1, last64bitsOfLastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentPlaintextString); //concatenate the last 64 bits of the last ciphertext and the current ciphertext (64+128=192 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			strcpy_s(concattedString, keyStringLength + 1, lastPlaintextString);
			strcat_s(concattedString, keyStringLength + 1, currentPlaintextString); //concatenate the last ciphertext and the current ciphertext (256 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastCiphertextString, ciphertextStringLength + 1, currentPlaintextString);
		free(currentPlaintextString);
	}
	//清理
	free(lastKeyString);
	free(lastCiphertextString);
}




// Monte Carlo Test: CBC
void aesCbcMCTEncrypt(int keySize, char* plaintextString, char* keyString, char* initailVectorString) {
	int plaintextStringLength = strlen(plaintextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initailVectorString);

	char* lastKeyString = malloc(keyStringLength + 1);
	char* lastPlaintextString = malloc(plaintextStringLength + 1);
	char* lastInitialVectorString = malloc(initialVectorStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength + 1, keyString);
	strcpy_s(lastPlaintextString, plaintextStringLength + 1, plaintextString);
	strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, initailVectorString);

	// 初始化AES
	if (register_cipher(&aes_desc) == -1) {
		printf("register AES error\n");
		return -1;
	}

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("initial vector: %s\n", lastInitialVectorString);
		printf("plaintext: %s\n", lastPlaintextString);

		char* currentCiphertextString = malloc(plaintextStringLength + 1);
		strcpy_s(currentCiphertextString, plaintextStringLength + 1, lastPlaintextString);
		char* lastCiphertextString = malloc(plaintextStringLength + 1);


		symmetric_CBC cbc;
		int err;

		for (int j = 0; j < 1000; j++) {
			strcpy_s(lastCiphertextString, plaintextStringLength + 1, currentCiphertextString);
			//aesEncrypt(AES_MODE_CBC, keySize, lastKeyString, lastPlaintextString, lastInitialVectorString, currentCiphertextString);
			


			char * plaintextByte = malloc(plaintextStringLength / 2);
			char * keyByte = malloc(keyStringLength / 2);
			char * initialVectorByte = malloc(initialVectorStringLength / 2);
			char * ciphertextByte = malloc(plaintextStringLength / 2); // 輸出的密文(長度和明文一樣)

			int plaintextByteLength;
			int keyByteLength;
			int initialVectorByteLength;
			hex_to_bytes(lastPlaintextString, plaintextByte, &plaintextByteLength);
			hex_to_bytes(lastKeyString, keyByte, &keyByteLength);
			hex_to_bytes(lastInitialVectorString, initialVectorByte, &initialVectorByteLength);


			
			if (j == 0) {
				// 初始化key
				if ((err = cbc_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, &cbc)) != CRYPT_OK) {
					printf("initialize key error: %s\n", error_to_string(err));
					return -1;
				}
			}
			

			// 加密
			if ((err = cbc_encrypt(plaintextByte, ciphertextByte, plaintextByteLength, &cbc)) != CRYPT_OK) {
				printf("encryption error: %s\n", error_to_string(err));
				return -1;
			}

			if (j == 999) {
				// 結束AES
				if ((err = cbc_done(&cbc)) != CRYPT_OK) {
					printf("cleaning error: %s\n", error_to_string(err));
					return -1;
				}
			}

			bytes_to_hex(ciphertextByte, plaintextByteLength, currentCiphertextString);
			
			
			if (j == 0) {
				strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastInitialVectorString);
			}
			else {
				strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastCiphertextString);
			}

			//清理
			free(plaintextByte);
			free(keyByte);
			free(initialVectorByte);
			free(ciphertextByte);
			
		}
		printf("ciphertext: %s\n", currentCiphertextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			xor_strings(nextKeyString, lastKeyString, currentCiphertextString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//one char in a hex string is 4 bits, in MCT test ciphertext is 128 bits(32 chars)
			//so to get the last 64 bits of the last ciphertext, we can just point to the 17th char
			char* last64bitsOfLastCiphertextString = lastCiphertextString + 16;
			strcpy_s(concattedString, keyStringLength + 1, last64bitsOfLastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString); //concatenate the last 64 bits of the last ciphertext and the current ciphertext (64+128=192 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			strcpy_s(concattedString, keyStringLength + 1, lastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString); //concatenate the last ciphertext and the current ciphertext (256 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastCiphertextString);
		strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, currentCiphertextString);
		free(currentCiphertextString);
	}
	//清理
	free(lastKeyString);
	free(lastPlaintextString);
	free(lastInitialVectorString);
}



void aesCbcMCTDecrypt(int keySize, char* ciphertextString, char* keyString, char* initailVectorString) {
	int ciphertextStringLength = strlen(ciphertextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initailVectorString);

	char* lastKeyString = malloc(keyStringLength + 1);
	char* lastCiphertextString = malloc(ciphertextStringLength + 1);
	char* lastInitialVectorString = malloc(initialVectorStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength + 1, keyString);
	strcpy_s(lastCiphertextString, ciphertextStringLength + 1, ciphertextString);
	strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, initailVectorString);

	// 初始化AES
	if (register_cipher(&aes_desc) == -1) {
		printf("register AES error\n");
		return -1;
	}

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("initial vector: %s\n", lastInitialVectorString);
		printf("ciphertext: %s\n", lastCiphertextString);

		char* currentPlaintextString = malloc(ciphertextStringLength + 1);
		strcpy_s(currentPlaintextString, ciphertextStringLength + 1, lastCiphertextString);
		char* lastPlaintextString = malloc(ciphertextStringLength + 1);

		symmetric_CBC cbc;
		int err;

		for (int j = 0; j < 1000; j++) {
			strcpy_s(lastPlaintextString, ciphertextStringLength + 1, currentPlaintextString);
			//aesDecrypt(AES_MODE_CBC, keySize, lastKeyString, lastCiphertextString, lastInitialVectorString, currentPlaintextString);
			
			char * ciphertextByte = malloc(ciphertextStringLength / 2);
			char * keyByte = malloc(keyStringLength / 2);
			char * initialVectorByte = malloc(initialVectorStringLength / 2);
			char * plaintextByte = malloc(ciphertextStringLength / 2); // 輸出的明文(長度和密文一樣)

			int ciphertextByteLength;
			int keyByteLength;
			int initialVectorByteLength;
			hex_to_bytes(lastCiphertextString, ciphertextByte, &ciphertextByteLength);
			hex_to_bytes(lastKeyString, keyByte, &keyByteLength);
			hex_to_bytes(lastInitialVectorString, initialVectorByte, &initialVectorByteLength);


			if (j == 0) {
				// 初始化key
				if ((err = cbc_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, &cbc)) != CRYPT_OK) {
					printf("initialize key error: %s\n", error_to_string(err));
					return -1;
				}
			}


			// 加密
			if ((err = cbc_decrypt( ciphertextByte, plaintextByte, ciphertextByteLength, &cbc)) != CRYPT_OK) {
				printf("encryption error: %s\n", error_to_string(err));
				return -1;
			}

			if (j == 999) {
				// 結束AES
				if ((err = cbc_done(&cbc)) != CRYPT_OK) {
					printf("cleaning error: %s\n", error_to_string(err));
					return -1;
				}
			}

			bytes_to_hex(plaintextByte, ciphertextByteLength, currentPlaintextString);


			if (j == 0) {
				strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastInitialVectorString);
			}
			else {
				strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastPlaintextString);
			}
		}
		printf("plaintext: %s\n", currentPlaintextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			xor_strings(nextKeyString, lastKeyString, currentPlaintextString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//one char in a hex string is 4 bits, in MCT test ciphertext is 128 bits(32 chars)
			//so to get the last 64 bits of the last ciphertext, we can just point to the 17th char
			char* last64bitsOfLastCiphertextString = lastPlaintextString + 16;
			strcpy_s(concattedString, keyStringLength + 1, last64bitsOfLastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentPlaintextString); //concatenate the last 64 bits of the last ciphertext and the current ciphertext (64+128=192 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			strcpy_s(concattedString, keyStringLength + 1, lastPlaintextString);
			strcat_s(concattedString, keyStringLength + 1, currentPlaintextString); //concatenate the last ciphertext and the current ciphertext (256 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastPlaintextString);
		strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, currentPlaintextString);
		free(currentPlaintextString);
	}
	//清理
	free(lastKeyString);
	free(lastCiphertextString);
}



//CBC Monte Carlo Test: CFB128
void aesCfb128MCTEncrypt(int keySize, char* plaintextString, char* keyString, char* initailVectorString) {
	int plaintextStringLength = strlen(plaintextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initailVectorString);

	char* lastKeyString = malloc(keyStringLength + 1);
	char* lastPlaintextString = malloc(plaintextStringLength + 1);
	char* lastInitialVectorString = malloc(initialVectorStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength + 1, keyString);
	strcpy_s(lastPlaintextString, plaintextStringLength + 1, plaintextString);
	strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, initailVectorString);

	// 初始化AES
	if (register_cipher(&aes_desc) == -1) {
		printf("register AES error\n");
		return -1;
	}

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("initial vector: %s\n", lastInitialVectorString);
		printf("plaintext: %s\n", lastPlaintextString);

		char* currentCiphertextString = malloc(plaintextStringLength + 1);
		strcpy_s(currentCiphertextString, plaintextStringLength + 1, lastPlaintextString);
		char* lastCiphertextString = malloc(plaintextStringLength + 1);


		symmetric_CFB cfb128;
		int err;

		for (int j = 0; j < 1000; j++) {
			strcpy_s(lastCiphertextString, plaintextStringLength + 1, currentCiphertextString);
			//aesEncrypt(AES_MODE_CBC, keySize, lastKeyString, lastPlaintextString, lastInitialVectorString, currentCiphertextString);



			char* plaintextByte = malloc(plaintextStringLength / 2);
			char* keyByte = malloc(keyStringLength / 2);
			char* initialVectorByte = malloc(initialVectorStringLength / 2);
			char* ciphertextByte = malloc(plaintextStringLength / 2); // 輸出的密文(長度和明文一樣)

			int plaintextByteLength;
			int keyByteLength;
			int initialVectorByteLength;
			hex_to_bytes(lastPlaintextString, plaintextByte, &plaintextByteLength);
			hex_to_bytes(lastKeyString, keyByte, &keyByteLength);
			hex_to_bytes(lastInitialVectorString, initialVectorByte, &initialVectorByteLength);
		
			if (j == 0) {
				// 初始化key
				if ((err = cfb_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, &cfb128)) != CRYPT_OK) {
					printf("initialize key error: %s\n", error_to_string(err));
					return -1;
				}
			}


			// 加密
			if ((err = cfb_encrypt(plaintextByte, ciphertextByte, plaintextByteLength, &cfb128)) != CRYPT_OK) {
				printf("encryption error: %s\n", error_to_string(err));
				return -1;
			}

			if (j == 999) {
				// 結束AES
				if ((err = cfb_done(&cfb128)) != CRYPT_OK) {
					printf("cleaning error: %s\n", error_to_string(err));
					return -1;
				}
			}

			bytes_to_hex(ciphertextByte, plaintextByteLength, currentCiphertextString);


			if (j == 0) {
				strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastInitialVectorString);
			}
			else {
				strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastCiphertextString);
			}

			//清理
			free(plaintextByte);
			free(keyByte);
			free(initialVectorByte);
			free(ciphertextByte);

		}
		printf("ciphertext: %s\n", currentCiphertextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			xor_strings(nextKeyString, lastKeyString, currentCiphertextString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//one char in a hex string is 4 bits, in MCT test ciphertext is 128 bits(32 chars)
			//so to get the last 64 bits of the last ciphertext, we can just point to the 17th char
			char* last64bitsOfLastCiphertextString = lastCiphertextString + 16;
			strcpy_s(concattedString, keyStringLength + 1, last64bitsOfLastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString); //concatenate the last 64 bits of the last ciphertext and the current ciphertext (64+128=192 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			strcpy_s(concattedString, keyStringLength + 1, lastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString); //concatenate the last ciphertext and the current ciphertext (256 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastCiphertextString);
		strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, currentCiphertextString);
		free(currentCiphertextString);
	}
	//清理
	free(lastKeyString);
	free(lastPlaintextString);
	free(lastInitialVectorString);
}

void aesCfb128MCTDecrypt(int keySize, char* ciphertextString, char* keyString, char* initailVectorString) {
	int ciphertextStringLength = strlen(ciphertextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initailVectorString);

	char* lastKeyString = malloc(keyStringLength + 1);
	char* lastCiphertextString = malloc(ciphertextStringLength + 1);
	char* lastInitialVectorString = malloc(initialVectorStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength + 1, keyString);
	strcpy_s(lastCiphertextString, ciphertextStringLength + 1, ciphertextString);
	strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, initailVectorString);

	// 初始化AES
	if (register_cipher(&aes_desc) == -1) {
		printf("register AES error\n");
		return -1;
	}

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("initial vector: %s\n", lastInitialVectorString);
		printf("ciphertext: %s\n", lastCiphertextString);

		char* currentPlaintextString = malloc(ciphertextStringLength + 1);
		strcpy_s(currentPlaintextString, ciphertextStringLength + 1, lastCiphertextString);
		char* lastPlaintextString = malloc(ciphertextStringLength + 1);

		symmetric_CFB cfb;
		int err;

		for (int j = 0; j < 1000; j++) {
			strcpy_s(lastPlaintextString, ciphertextStringLength + 1, currentPlaintextString);
			//aesDecrypt(AES_MODE_CBC, keySize, lastKeyString, lastCiphertextString, lastInitialVectorString, currentPlaintextString);

			char* ciphertextByte = malloc(ciphertextStringLength / 2);
			char* keyByte = malloc(keyStringLength / 2);
			char* initialVectorByte = malloc(initialVectorStringLength / 2);
			char* plaintextByte = malloc(ciphertextStringLength / 2); // 輸出的明文(長度和密文一樣)

			int ciphertextByteLength;
			int keyByteLength;
			int initialVectorByteLength;
			hex_to_bytes(lastCiphertextString, ciphertextByte, &ciphertextByteLength);
			hex_to_bytes(lastKeyString, keyByte, &keyByteLength);
			hex_to_bytes(lastInitialVectorString, initialVectorByte, &initialVectorByteLength);


			if (j == 0) {
				// 初始化key
				if ((err = cfb_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, &cfb)) != CRYPT_OK) {
					printf("initialize key error: %s\n", error_to_string(err));
					return -1;
				}
			}


			// 解密
			if ((err = cfb_decrypt(ciphertextByte, plaintextByte, ciphertextByteLength, &cfb)) != CRYPT_OK) {
				printf("encryption error: %s\n", error_to_string(err));
				return -1;
			}

			if (j == 999) {
				// 結束AES
				if ((err = cfb_done(&cfb)) != CRYPT_OK) {
					printf("cleaning error: %s\n", error_to_string(err));
					return -1;
				}
			}

			bytes_to_hex(plaintextByte, ciphertextByteLength, currentPlaintextString);


			if (j == 0) {
				strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastInitialVectorString);
			}
			else {
				strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastPlaintextString);
			}
		}
		printf("plaintext: %s\n", currentPlaintextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			xor_strings(nextKeyString, lastKeyString, currentPlaintextString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//one char in a hex string is 4 bits, in MCT test ciphertext is 128 bits(32 chars)
			//so to get the last 64 bits of the last ciphertext, we can just point to the 17th char
			char* last64bitsOfLastCiphertextString = lastPlaintextString + 16;
			strcpy_s(concattedString, keyStringLength + 1, last64bitsOfLastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentPlaintextString); //concatenate the last 64 bits of the last ciphertext and the current ciphertext (64+128=192 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			strcpy_s(concattedString, keyStringLength + 1, lastPlaintextString);
			strcat_s(concattedString, keyStringLength + 1, currentPlaintextString); //concatenate the last ciphertext and the current ciphertext (256 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastPlaintextString);
		strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, currentPlaintextString);
		free(currentPlaintextString);
	}
	//清理
	free(lastKeyString);
	free(lastCiphertextString);
}


//CBC Monte Carlo Test: CFB8
void aesCfb8MCTEncrypt(int keySize, char* plaintextString, char* keyString, char* initailVectorString) {
	int plaintextStringLength = strlen(plaintextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initailVectorString);

	char* lastKeyString = malloc(keyStringLength + 1);
	char* lastPlaintextString = malloc(plaintextStringLength + 1);
	char* lastInitialVectorString = malloc(initialVectorStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength + 1, keyString);
	strcpy_s(lastPlaintextString, plaintextStringLength + 1, plaintextString);
	strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, initailVectorString);

	// 初始化AES
	if (register_cipher(&aes_desc) == -1) {
		printf("register AES error\n");
		return -1;
	}

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("initial vector: %s\n", lastInitialVectorString);
		printf("plaintext: %s\n", lastPlaintextString);

		char* currentCiphertextString = malloc(plaintextStringLength + 1);
		strcpy_s(currentCiphertextString, plaintextStringLength + 1, lastPlaintextString);
		char* lastCiphertextStringsList[32];

		// 初始化lastCiphertextStringsList
		for (int j = 0; j < 32; j++) {
			lastCiphertextStringsList[j] = malloc(plaintextStringLength + 1);
			strcpy_s(lastCiphertextStringsList[j], plaintextStringLength + 1, "");
		}


		symmetric_CFB cfb8;
		int err;
		unsigned char initialVectorBufferByte[16]; //16byte的buffer
		unsigned char middleResultByte[16]; //16byte的buffer

		for (int j = 0; j < 1000; j++) {
			//aesEncrypt(AES_MODE_CBC, keySize, lastKeyString, lastPlaintextString, lastInitialVectorString, currentCiphertextString);
			//更新lastCiphertextStringsList
			for (int k = 31; k > 0; k--) {
				strcpy_s(lastCiphertextStringsList[k], plaintextStringLength + 1, lastCiphertextStringsList[k - 1]);
			}
			strcpy_s(lastCiphertextStringsList[0], plaintextStringLength + 1, currentCiphertextString);


			char* plaintextByte = malloc(plaintextStringLength / 2);
			char* keyByte = malloc(keyStringLength / 2);
			char* initialVectorByte = malloc(initialVectorStringLength / 2);
			char* ciphertextByte = malloc(plaintextStringLength / 2); // 輸出的密文(長度和明文一樣)

			int plaintextByteLength;
			int keyByteLength;
			int initialVectorByteLength;
			hex_to_bytes(lastPlaintextString, plaintextByte, &plaintextByteLength);
			hex_to_bytes(lastKeyString, keyByte, &keyByteLength);
			hex_to_bytes(lastInitialVectorString, initialVectorByte, &initialVectorByteLength);

			

			if (j == 0) {
				memcpy(initialVectorBufferByte, initialVectorByte, 16); //複製initialVectorByte到initialVectorBufferByte
				// 初始化key
				if ((err = ecb_start(find_cipher("aes"), keyByte, keyByteLength, 0, &cfb8)) != CRYPT_OK) {
					printf("initialize key error: %s\n", error_to_string(err));
					return -1;
				}
			}


			// 加密
			//逐個byte加密
			for (int i = 0; i < plaintextByteLength; i++) {
				//加密
				if ((err = ecb_encrypt(initialVectorBufferByte, middleResultByte, 16, &cfb8)) != CRYPT_OK) {
					printf("encryption error: %s\n", error_to_string(err));
					return -1;
				}
				//把middleResultBufferByte的第一個byte存到ciphertextByte
				ciphertextByte[i] = middleResultByte[0] ^ plaintextByte[i];

				// initialVector = { initialVector[1], initialVector[2], ..., initialVector[15], ciphertextByte[i] }
				//先左移一個byte
				for (int j = 0; j < 15; j++) {
					initialVectorBufferByte[j] = initialVectorBufferByte[j + 1];
				}
				//把ciphertextByte[i]存到最後一個byte
				initialVectorBufferByte[15] = ciphertextByte[i];

			}

			if (j == 999) {
				// 結束AES
				if ((err = ecb_done(&cfb8)) != CRYPT_OK) {
					printf("cleaning error: %s\n", error_to_string(err));
					return -1;
				}
			}

			bytes_to_hex(ciphertextByte, plaintextByteLength, currentCiphertextString);

			if (j < 16) {
				getIthByteInHex(lastInitialVectorString, j, lastPlaintextString);  //j-th byte of initialVector
			}
			else {
				strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastCiphertextStringsList[15]); //lastCiphertextStringsList[15] is the 16th ciphertext
			}

			//清理
			free(plaintextByte);
			free(keyByte);
			free(initialVectorByte);
			free(ciphertextByte);
			

		}
		printf("ciphertext: %s\n", currentCiphertextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//Key[i+1] = Key[i] xor (CT[j-15] || CT[j-14] || … || CT[j])
			//CT[j] 是 currentCiphertextString
			//CT[j-1] 是 lastCiphertextStringsList[0]
			//CT[j-15] 是 lastCiphertextStringsList[14]
			strcpy_s(concattedString, keyStringLength + 1, "");
			for (int k = 14; k >= 0; k--) {
				strcat_s(concattedString, keyStringLength + 1, lastCiphertextStringsList[k]);
			}
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString);

			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//Key[i+1] = Key[i] xor (CT[j-23] || CT[j-22] || … || CT[j])
			//CT[j] 是 currentCiphertextString
			//CT[j-1] 是 lastCiphertextStringsList[0]
			//CT[j-23] 是 lastCiphertextStringsList[22]
			strcpy_s(concattedString, keyStringLength + 1, "");
			for (int k = 22; k >= 0; k--) {
				strcat_s(concattedString, keyStringLength + 1, lastCiphertextStringsList[k]);
			}
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString);

			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			

			//Key[i+1] = Key[i] xorKey[i+1] = Key[i] xor (CT[j-31] || CT[j-30] || … || CT[j])
			//CT[j] 是 currentCiphertextString
			//CT[j-1] 是 lastCiphertextStringsList[0]
			//CT[j-31] 是 lastCiphertextStringsList[30]
			strcpy_s(concattedString, keyStringLength + 1, "");
			for (int k = 30; k >= 0; k--) {
				strcat_s(concattedString, keyStringLength + 1, lastCiphertextStringsList[k]);
			}
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString);
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastCiphertextStringsList[15]);

		//IV[i+1] = (CT[j-15] || CT[j-14]  || … || CT[j])
		//CT[j] 是 currentCiphertextString
		//CT[j-1] 是 lastCiphertextStringsList[0]
		//CT[j-15] 是 lastCiphertextStringsList[14]
		char* concattedString = malloc(keyStringLength + 1);
		strcpy_s(concattedString, keyStringLength + 1, "");
		for (int k = 14; k >= 0; k--) {
			strcat_s(concattedString, keyStringLength + 1, lastCiphertextStringsList[k]);
		}
		strcat_s(concattedString, keyStringLength + 1, currentCiphertextString);
		strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, concattedString);
		free(currentCiphertextString);
		free(concattedString);
		for (int k = 0; k < 32; k++) {
			free(lastCiphertextStringsList[k]);
		}
	}
	//清理
	free(lastKeyString);
	free(lastPlaintextString);
	free(lastInitialVectorString);

	
}




//Monte Carlo Test: CTR
void aesCtrMCTEncrypt(int keySize, char* plaintextString, char* keyString, char* initailVectorString) {
	int plaintextStringLength = strlen(plaintextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initailVectorString);

	char* lastKeyString = malloc(keyStringLength + 1);
	char* lastPlaintextString = malloc(plaintextStringLength + 1);
	char* lastInitialVectorString = malloc(initialVectorStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength + 1, keyString);
	strcpy_s(lastPlaintextString, plaintextStringLength + 1, plaintextString);
	strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, initailVectorString);

	// 初始化AES
	if (register_cipher(&aes_desc) == -1) {
		printf("register AES error\n");
		return -1;
	}

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("initial vector: %s\n", lastInitialVectorString);
		printf("plaintext: %s\n", lastPlaintextString);

		char* currentCiphertextString = malloc(plaintextStringLength + 1);
		strcpy_s(currentCiphertextString, plaintextStringLength + 1, lastPlaintextString);
		char* lastCiphertextString = malloc(plaintextStringLength + 1);


		symmetric_CTR ctr;
		ctr.padlen = 0; //不使用padding
		int err;

		for (int j = 0; j < 1000; j++) {
			strcpy_s(lastCiphertextString, plaintextStringLength + 1, currentCiphertextString);
			//aesEncrypt(AES_MODE_CBC, keySize, lastKeyString, lastPlaintextString, lastInitialVectorString, currentCiphertextString);



			char* plaintextByte = malloc(plaintextStringLength / 2);
			char* keyByte = malloc(keyStringLength / 2);
			char* initialVectorByte = malloc(initialVectorStringLength / 2);
			char* ciphertextByte = malloc(plaintextStringLength / 2); // 輸出的密文(長度和明文一樣)

			int plaintextByteLength;
			int keyByteLength;
			int initialVectorByteLength;
			hex_to_bytes(lastPlaintextString, plaintextByte, &plaintextByteLength);
			hex_to_bytes(lastKeyString, keyByte, &keyByteLength);
			hex_to_bytes(lastInitialVectorString, initialVectorByte, &initialVectorByteLength);


			if (j == 0) {
				// 初始化key
				if ((err = ctr_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
					printf("initialize key error: %s\n", error_to_string(err));
					return -1;
				}
			}


			// 加密
			if ((err = ctr_encrypt(plaintextByte, ciphertextByte, plaintextByteLength, &ctr)) != CRYPT_OK) {
				printf("encryption error: %s\n", error_to_string(err));
				return -1;
			}

			if (j == 999) {
				// 結束AES
				if ((err = ctr_done(&ctr)) != CRYPT_OK) {
					printf("cleaning error: %s\n", error_to_string(err));
					return -1;
				}
			}

			bytes_to_hex(ciphertextByte, plaintextByteLength, currentCiphertextString);


			if (j == 0) {
				strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastInitialVectorString);
			}
			else {
				strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastCiphertextString);
			}

			//清理
			free(plaintextByte);
			free(keyByte);
			free(initialVectorByte);
			free(ciphertextByte);

		}
		printf("ciphertext: %s\n", currentCiphertextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			xor_strings(nextKeyString, lastKeyString, currentCiphertextString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//one char in a hex string is 4 bits, in MCT test ciphertext is 128 bits(32 chars)
			//so to get the last 64 bits of the last ciphertext, we can just point to the 17th char
			char* last64bitsOfLastCiphertextString = lastCiphertextString + 16;
			strcpy_s(concattedString, keyStringLength + 1, last64bitsOfLastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString); //concatenate the last 64 bits of the last ciphertext and the current ciphertext (64+128=192 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			strcpy_s(concattedString, keyStringLength + 1, lastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentCiphertextString); //concatenate the last ciphertext and the current ciphertext (256 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastPlaintextString, plaintextStringLength + 1, lastCiphertextString);
		strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, currentCiphertextString);
		free(currentCiphertextString);
	}
	//清理
	free(lastKeyString);
	free(lastPlaintextString);
	free(lastInitialVectorString);
}

void aesCtrMCTDecrypt(int keySize, char* ciphertextString, char* keyString, char* initailVectorString) {
	int ciphertextStringLength = strlen(ciphertextString);
	int keyStringLength = strlen(keyString);
	int initialVectorStringLength = strlen(initailVectorString);

	char* lastKeyString = malloc(keyStringLength + 1);
	char* lastCiphertextString = malloc(ciphertextStringLength + 1);
	char* lastInitialVectorString = malloc(initialVectorStringLength + 1);

	strcpy_s(lastKeyString, keyStringLength + 1, keyString);
	strcpy_s(lastCiphertextString, ciphertextStringLength + 1, ciphertextString);
	strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, initailVectorString);

	// 初始化AES
	if (register_cipher(&aes_desc) == -1) {
		printf("register AES error\n");
		return -1;
	}

	for (int i = 0; i < 100; i++) {
		printf("round %d\n", i);
		printf("key: %s\n", lastKeyString);
		printf("initial vector: %s\n", lastInitialVectorString);
		printf("ciphertext: %s\n", lastCiphertextString);

		char* currentPlaintextString = malloc(ciphertextStringLength + 1);
		strcpy_s(currentPlaintextString, ciphertextStringLength + 1, lastCiphertextString);
		char* lastPlaintextString = malloc(ciphertextStringLength + 1);

		symmetric_CTR ctr;
		int err;

		for (int j = 0; j < 1000; j++) {
			strcpy_s(lastPlaintextString, ciphertextStringLength + 1, currentPlaintextString);
			//aesDecrypt(AES_MODE_CBC, keySize, lastKeyString, lastCiphertextString, lastInitialVectorString, currentPlaintextString);

			char* ciphertextByte = malloc(ciphertextStringLength / 2);
			char* keyByte = malloc(keyStringLength / 2);
			char* initialVectorByte = malloc(initialVectorStringLength / 2);
			char* plaintextByte = malloc(ciphertextStringLength / 2); // 輸出的明文(長度和密文一樣)

			int ciphertextByteLength;
			int keyByteLength;
			int initialVectorByteLength;
			hex_to_bytes(lastCiphertextString, ciphertextByte, &ciphertextByteLength);
			hex_to_bytes(lastKeyString, keyByte, &keyByteLength);
			hex_to_bytes(lastInitialVectorString, initialVectorByte, &initialVectorByteLength);


			if (j == 0) {
				// 初始化key
				if ((err = ctr_start(find_cipher("aes"), initialVectorByte, keyByte, keyByteLength, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
					printf("initialize key error: %s\n", error_to_string(err));
					return -1;
				}
			}


			// 解密
			if ((err = ctr_decrypt(ciphertextByte, plaintextByte, ciphertextByteLength, &ctr)) != CRYPT_OK) {
				printf("encryption error: %s\n", error_to_string(err));
				return -1;
			}

			if (j == 999) {
				// 結束AES
				if ((err = ctr_done(&ctr)) != CRYPT_OK) {
					printf("cleaning error: %s\n", error_to_string(err));
					return -1;
				}
			}

			bytes_to_hex(plaintextByte, ciphertextByteLength, currentPlaintextString);


			if (j == 0) {
				strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastInitialVectorString);
			}
			else {
				strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastPlaintextString);
			}
		}
		printf("plaintext: %s\n", currentPlaintextString);
		if (keySize == AES_KEY_SIZE_128) {
			char* nextKeyString = malloc(keyStringLength + 1);
			xor_strings(nextKeyString, lastKeyString, currentPlaintextString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
		}
		else if (keySize == AES_KEY_SIZE_192)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			//one char in a hex string is 4 bits, in MCT test ciphertext is 128 bits(32 chars)
			//so to get the last 64 bits of the last ciphertext, we can just point to the 17th char
			char* last64bitsOfLastCiphertextString = lastPlaintextString + 16;
			strcpy_s(concattedString, keyStringLength + 1, last64bitsOfLastCiphertextString);
			strcat_s(concattedString, keyStringLength + 1, currentPlaintextString); //concatenate the last 64 bits of the last ciphertext and the current ciphertext (64+128=192 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else if (keySize == AES_KEY_SIZE_256)
		{
			char* nextKeyString = malloc(keyStringLength + 1);
			char* concattedString = malloc(keyStringLength + 1);
			strcpy_s(concattedString, keyStringLength + 1, lastPlaintextString);
			strcat_s(concattedString, keyStringLength + 1, currentPlaintextString); //concatenate the last ciphertext and the current ciphertext (256 bits)
			xor_strings(nextKeyString, lastKeyString, concattedString, keyStringLength);
			strcpy_s(lastKeyString, keyStringLength + 1, nextKeyString);
			free(nextKeyString);
			free(concattedString);
		}
		else
		{
			printf("unknown key size\n");
			return;
		}
		strcpy_s(lastCiphertextString, ciphertextStringLength + 1, lastPlaintextString);
		strcpy_s(lastInitialVectorString, initialVectorStringLength + 1, currentPlaintextString);
		free(currentPlaintextString);
	}
	//清理
	free(lastKeyString);
	free(lastCiphertextString);
}




