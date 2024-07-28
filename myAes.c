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

