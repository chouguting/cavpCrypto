#include <tomcrypt.h>

void ecdsaKeyPair()
{
	ecc_key mykey;
	prng_state prng;
	int err;
	const ltc_ecc_curve* curve;
	unsigned char qx[32], qy[32], d[32];
	int i;
	crypt_mp_init("ltm"); //使用libtommath

	
	/* register yarrow */
	if (register_prng(&yarrow_desc) == -1) {
		printf("Error registering Yarrow\n");
		return-1;
	}
	/* 設定PRNG */
	if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL))
		!= CRYPT_OK) {
		printf("Error setting up PRNG, %s\n", error_to_string(err));
		return-1;
	}

	// 獲取P - 256曲線
	if ((err = ecc_find_curve("P-256", &curve)) != CRYPT_OK) {
		printf("Error finding P-256 curve: %s\n", error_to_string(err));
		return -1;
	}

	/* 產生ECC key */
	if ((err = ecc_make_key_ex(&prng, find_prng("yarrow"), &mykey, curve)) != CRYPT_OK) {
		printf("Error generating P-256 ECC keypair: %s\n", error_to_string(err));
		return -1;
	}



	// 獲取公鑰的qx、qy和私鑰d
    
    ltc_mp.unsigned_write(mykey.pubkey.x, qx);
    ltc_mp.unsigned_write(mykey.pubkey.y, qy);
    ltc_mp.unsigned_write(mykey.k, d);

    // 印出qx、qy和d
	printf("qx:");
    for (i = 0; i < 32; i++) printf("%02X", qx[i]);
    printf("\n");
	printf("qy:");
    for (i = 0; i < 32; i++) printf("%02X", qy[i]);
    printf("\n");
	printf("d:");
    for (i = 0; i < 32; i++) printf("%02X", d[i]);
    printf("\n");

    // 釋放key
    ecc_free(&mykey);

}