
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
	
	ecdsaKeyPair(ECDSA_CURVE_P521);
	
	char* qx = "01572B37F84D7682331500C7CCF0BB73791AE654B2725B85AE8A9405ADA73424EEA0BFB72EE278E093332F89D72D0DE96CF2CECD4A73031A92C43F6D17CBB9B4AC82";
	char* qy = "B755308AB6DA4BD39758FD1BB44B9F3B1D94614AAE353148C8CD90777A48EEA9814C34A72D627191B84E24029846F2C0840D862296FA023E6D0C89649765DE70ACCD";
	int result = ecdsaKeyVerify(ECDSA_CURVE_P521, qx, qy); //1
	printf("result: %d\n", result);  
	


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
	
	
}
