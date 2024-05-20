
#include "stdio.h"
#include "string.h"
#include "myEcdsa.h"
#include "myRsa.h"


int main()
{
	char* qx = "57657A29BDB28F45765B89A3CF84EBBD4139EC455CE2DB2B7A9B79472195614F";
	char* qy = "009EFEC63E4042BB8D9D08188BE5114BF95EF2570F8B67F7F2CDF3ED6DF7C137ED";
	//int result = ecdsaKeyVerify(ECDSA_CURVE_P256, qx,  qy);
	int result = 1;
	ecdsaKeyPair(1);
	printf("result: %d\n", result);
}

