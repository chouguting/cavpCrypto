
#include "stdio.h"
#include "string.h"
#include "myEcdsa.h"
#include "mySha.h"
#include "myShake.h"
#include "myAes.h"
#include <string.h>
#include "myRsa.h"
#include <tomcrypt.h>
#include <tommath.h>
#include "utils.h"

// Visual Studio 有BUG，從Github上下載本專案後會無法編譯
// 解決方法：Windows偵錯工具右邊有個下拉選單，選擇cavpCrypto偵錯屬性，把C語言標準調成比較新的，就可以編譯了
// 很奇怪的是，如果你編譯成功後，再把C語言標準調回原本的，再編譯一次，也會成功 (很奇怪吧😶😶😶😶😶)

int main()
{
	/*
	//encrypt
	printf("encrypt\n");
	char* plaintext = "3FEB964D7DF5AF8364A263C3D7CFBE37";
	char* key = "6C35C021B948C7B93BFB016EE31AAEF79741CFD0874CD3913DDE8CA9BE28B9CB";
	char* initialVector = "B3941A16EF4591E0ABBA7E69E13C1445";
	char ciphertext[1024];
	aesEncrypt(AES_MODE_CTR, AES_KEY_SIZE_256, key, plaintext,initialVector, ciphertext);
	printf("ciphertext: %s\n", ciphertext);

	//decrypt
	printf("decrypt\n");
	char* ciphertext2 = "BD49295006250FFCA5100B6007A0EADE";
	char* key2 = "FFFFFF8000000000000000000000000000000000000000000000000000000000";
	char* initialVector2 = "00000000000000000000000000000000";
	char plaintext2[513];
	strcpy_s(plaintext2, 512, "");
	aesDecrypt(AES_MODE_CTR, AES_KEY_SIZE_256, key2, ciphertext2, initialVector2, plaintext2);
	printf("plaintext: %s\n", plaintext2);
	*/


	//MCT test
	/*char* mctPlaintext = "C9";
	char* mctKey = "C5D36D30F9D33D631FF5367693674949";
	char* mctInitialVector = "21FB30122A624B7A071BDD763D1F047A";*/

	//aesCfb128MCTEncrypt(AES_KEY_SIZE_192, mctPlaintext, mctKey, mctInitialVector);
	//aesCfb8MCTEncrypt(AES_KEY_SIZE_128, mctPlaintext, mctKey, mctInitialVector);


	//char* mctCiphertext = "AA4D5E000E28E3856E36110D80732E61";
	//char* mctKey2 = "4AFC928203A640E26DC0752E78484D4349B946334C4C77297EDEA3A8FE3C6519";
	//char * mctInitialVector2 = "3F3BEAC49657F44FBE44B582B4ECEB61";

	//aesCfb128MCTDecrypt(AES_KEY_SIZE_256, mctCiphertext, mctKey2, mctInitialVector2);
	
	int err;
	rsa_key key;
	prng_state prng;
	//ltc_mp = tfm_desc;
	crypt_mp_init("ltm"); //使用libtommath
	
	unsigned long* sig_len;
	//char* message = "0267A8B7429FBBAB3EF24B794E83BB70D9AB3A6DA947EA3585D00CBB7F152FD955A9AEF0DCAFFFCA1F32536F85D1";
	//char* test = rsaSignMessage_pkcs1_v1_5(message, SHA3_256, &sig_len);
	
	/*hash test*/
	unsigned char hash[2048];      // Buffer to hold the SHA-256 hash (32 bytes for SHA-256)
	hash_state sha384_state;     // Hash state object
	const char* message = "ABCD1234";  // Message to hash
	int messageBytesLen;
	unsigned char* messageBytes = malloc(strlen(message) / 2);
	hex_to_bytes(message, messageBytes, &messageBytesLen);
	// Step 1: Initialize the SHA-256 hash function
	if ((err = sha384_init(&sha384_state)) != CRYPT_OK) {
		printf("Error initializing SHA-384: %s\n", error_to_string(err));
		return -1;
	}

	// Step 2: Process the message (you can call this function multiple times to process large data)
	if ((err = sha384_process(&sha384_state, (unsigned char*)messageBytes, messageBytesLen)) != CRYPT_OK) {
		printf("Error processing SHA-384: %s\n", error_to_string(err));
		return -1;
	}

	// Step 3: Finalize the hash (this computes the final hash and stores it in the buffer)
	if ((err = sha384_done(&sha384_state, hash)) != CRYPT_OK) {
		printf("Error finalizing SHA-384: %s\n", error_to_string(err));
		return -1;
	}

	// Step 4: Print the resulting SHA-256 hash in hexadecimal format
	printf("SHA-384 hash of '%s':\n", message);
	for (int i = 0; i < 384/8; i++) {
		printf("%02x", hash[i]);
	}
	printf("\n");

	unsigned char hash2[1025];
	int* outhashlen;
	shaHash(SHA2_384, message, hash2, &outhashlen);
	printf("GORDON-SHA-384 hash of '%s':\n", message);
	printf("GORDON-SHA-384 hash of '%s':\n", hash2);
	printf("\n");
}
