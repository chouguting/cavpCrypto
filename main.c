
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
	/*aesCfb8MCTEncrypt(AES_KEY_SIZE_128, mctPlaintext, mctKey, mctInitialVector);


	char* mctCiphertext = "AA4D5E000E28E3856E36110D80732E61";
	char* mctKey2 = "4AFC928203A640E26DC0752E78484D4349B946334C4C77297EDEA3A8FE3C6519";
	char * mctInitialVector2 = "3F3BEAC49657F44FBE44B582B4ECEB61";*/

	//aesCfb128MCTDecrypt(AES_KEY_SIZE_256, mctCiphertext, mctKey2, mctInitialVector2);
	char* message = "16918EC58F1E207306AB0D9FC3A1626D2BCF5D24AB7BAB1B29A425AA0DA69581AF1A6830B55217034CDD50987E3D6784EA78DBFECB30237FC24418A7216C5056448CDC2A254DE607CD2954CEFA6E5F414C47165EFDDA0E8C458D7D9C59E52CA1AC4B06DE7FB3CC01D6D9D8D9BC680D40E0718C4E0EFDA14B6A5CDEF14EBDE0A5";
	unsigned long messagelen;
	unsigned long* siglen;
	//char* test = rsaSignMessage_pkcs1_v1_5(message, SHA2_256, &siglen);
	rsa_key key;
	prng_state prng;
	int err;

	// Initialize the RNG
	if (register_prng(&yarrow_desc) == -1) {
		printf("Error registering Yarrow\n");
		return;
	}
	/* 設定PRNG */
	if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL))
		!= CRYPT_OK) {
		printf("Error setting up PRNG, %s\n", error_to_string(err));
		return;
	}

	// Generate RSA key
	if ((err = rsa_make_key(&prng, find_prng("sprng"), 2048 / 8, 65537, &key)) != CRYPT_OK) {
		printf("Error generating ECC keypair: %s\n", error_to_string(err));
		return -1;
	}
}
