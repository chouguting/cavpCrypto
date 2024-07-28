
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
	char* plaintext = "C336D3973BB1D1FE1FF0A3625DE9ED4C42996B4F75BBF227E07AC32FECA2905C";
	char* key = "6FB482165C508876C4919F173B2627EB";
	char* initialVector = "53493F125EEE839FB93391BCC6F228A7";
	char ciphertext[1024];
	strcpy_s(ciphertext, 512, "");
	aesEncrypt(AES_MODE_CTR,AES_KEY_SIZE_128, key, plaintext,initialVector, ciphertext);
	printf("ciphertext: %s\n", ciphertext);

	//decrypt
	printf("decrypt\n");
	char* ciphertext2 = "6F2014DF05BF15D676FF697FB39A72693DAC00C8F075DEC1788EDA7AD89ECD039E07624D42153D3082557716D23330C95AC84FCCF7530CD26D56F543EF982BED153BB2E464CC318D79F81BFC474C186DD1CA13038CE33F51EBC61A73A3B6289E51BF62EAA002946DCBDCB036A5F89988CA98F918367DAC772653E6F83AFC69292EC1F4E0D4E206CBE34980385A65A5D2BF55700DE0575F46A036CDA7CD78B74C";
	char* key2 = "AC98881B640128CE9A1E53C8DBD9D7912FBA64013711BAA2EEDFF0B0FFF3B504";
	char* initialVector2 = "7174C757C410AB92798CAC0D12EB06BE";
	char plaintext2[513];
	strcpy_s(plaintext2, 512, "");
	aesDecrypt(AES_MODE_CTR, AES_KEY_SIZE_256, key2, ciphertext2, initialVector2, plaintext2);
	printf("plaintext: %s\n", plaintext2);
	
}

