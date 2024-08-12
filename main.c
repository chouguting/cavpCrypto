
#include "stdio.h"
#include "string.h"
#include "myEcdsa.h"
#include "mySha.h"
#include "myShake.h"
#include "myAes.h"
#include <string.h>

// Visual Studio 有BUG，從Github上下載本專案後會無法編譯
// 解決方法：Windows偵錯工具右邊有個下拉選單，選擇cavpCrypto偵錯屬性，把C語言標準調成比較新的，就可以編譯了
// 很奇怪的是，如果你編譯成功後，再把C語言標準調回原本的，再編譯一次，也會成功 (很奇怪吧😶😶😶😶😶)

int main()
{
	
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
	


	//MCT test
	char* mctPlaintext = "3E999BFA92248C700FDA73AACDF6FE3C";
	char* mctKey = "93D5DFAE5D069713A68CA6003214AE4F97A39767A5A88C95";

	//aesEcbMCTEncrypt(AES_MODE_ECB, AES_KEY_SIZE_192, mctPlaintext, mctKey);


	char* mctCiphertext = "68B3B62348A202575DAB209CADE5F5F9";
	char* mctKey2 = "7F56A5039DCA92CFD3D15BA8168EBC99B879EDE1D6F92D70F4C0A01674550A23";
	aesEcbMCTDecrypt(AES_KEY_SIZE_256, mctCiphertext, mctKey2);
	
	
}

