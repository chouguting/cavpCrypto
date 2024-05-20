
#include "stdio.h"
#include "string.h"
#include "myEcdsa.h"


// Visual Studio 有BUG，從Github上下載本專案後會無法編譯
// 解決方法：畚箕Windows偵錯工具右邊有個下拉選單，選擇cavpCrypto偵錯屬性，把C語言標準調成比較新的，就可以編譯了
// 很奇怪的是，如果你編譯成功後，再把C語言標準調回原本的，再編譯一次，也會成功 (很奇怪吧😶😶😶😶😶)

int main()
{
	char* qx = "57657A29BDB28F45765B89A3CF84EBBD4139EC455CE2DB2B7A9B79472195614F";
	char* qy = "009EFEC63E4042BB8D9D08188BE5114BF95EF2570F8B67F7F2CDF3ED6DF7C137ED";
	int result = ecdsaKeyVerify(ECDSA_CURVE_P256, qx,  qy);
	printf("result: %d\n", result);
}

