#include <tomcrypt.h>
#include <tommath.h>
#include "myEcdsa.h"
#include "utils.h"


const int ECDSA_CURVE_P256 = 1;
const int ECDSA_CURVE_P384 = 2;
const int ECDSA_CURVE_P521 = 3;

void ecdsaKeyPair(int keypairCurve)
{
	ecc_key mykey;
	prng_state prng;
	int err;
	const ltc_ecc_curve* curve;
	unsigned char* qx, * qy, * d;
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
	if (keypairCurve == ECDSA_CURVE_P256)
	{
		if ((err = ecc_find_curve("P-256", &curve)) != CRYPT_OK) {
			printf("Error finding P-256 curve: %s\n", error_to_string(err));
			return -1;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P384) // 獲取P - 384曲線
	{
		if ((err = ecc_find_curve("P-384", &curve)) != CRYPT_OK) {
			printf("Error finding P-384 curve: %s\n", error_to_string(err));
			return -1;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P521) // 獲取P - 521曲線
	{
		if ((err = ecc_find_curve("P-521", &curve)) != CRYPT_OK) {
			printf("Error finding P-521 curve: %s\n", error_to_string(err));
			return -1;
		}
		
	}
	else
	{
		printf("Error finding curve: %s\n", error_to_string(err));
		return -1;
	}
	
	/* 產生ECC key */
	if ((err = ecc_make_key_ex(&prng, find_prng("yarrow"), &mykey, curve)) != CRYPT_OK) {
		printf("Error generating ECC keypair: %s\n", error_to_string(err));
		return -1;
	}

	// 獲取公鑰的qx、qy和私鑰d
	int qx_size = ltc_mp.unsigned_size(mykey.pubkey.x);
	qx = malloc(qx_size);
	ltc_mp.unsigned_write(mykey.pubkey.x, qx);

	int qy_size = ltc_mp.unsigned_size(mykey.pubkey.y);
	qy = malloc(qy_size);
	ltc_mp.unsigned_write(mykey.pubkey.y, qy);

	int d_size = ltc_mp.unsigned_size(mykey.k);
	d = malloc(d_size);
	ltc_mp.unsigned_write(mykey.k, d);
    
    ltc_mp.unsigned_write(mykey.pubkey.x, qx);
    ltc_mp.unsigned_write(mykey.pubkey.y, qy);
    ltc_mp.unsigned_write(mykey.k, d);

	// 印出qx、qy和d
	printf("qx:");
	for (i = 0; i < qx_size; i++) printf("%02X", qx[i]);
	printf("\n");
	printf("qy:");
	for (i = 0; i < qy_size; i++) printf("%02X", qy[i]);
	printf("\n");
	printf("d:");
	for (i = 0; i < d_size; i++) printf("%02X", d[i]);
	printf("\n");
    

    // 釋放key
    ecc_free(&mykey);
	free(qx);
	free(qy);
	free(d);
}


int ecdsaKeyVerify(int keypairCurve, char* qx, char* qy) {
	const ltc_ecc_curve* curve;
	mp_int x,  y;
	int err;



	crypt_mp_init("ltm"); //使用libtommath
	

	int keysize = (keypairCurve == ECDSA_CURVE_P256) ? 32 : (keypairCurve == ECDSA_CURVE_P384) ? 48 : (keypairCurve == ECDSA_CURVE_P521) ? 66 : 0;

	//檢查長度
	/*
	if (strlen(qx) != 2 * keysize || strlen(qy) != 2 * keysize) { //1個byte是2個hex
		//printf("Invalid key length\n");
		return false;
	}*/

	// 根據keypairCurve選擇對應的曲線
	if (keypairCurve == ECDSA_CURVE_P256) {
		if ((err = ecc_find_curve("P-256", &curve)) != CRYPT_OK) {
			//printf("Error finding P-256 curve: %s\n", error_to_string(err));
			return false;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P384) {
		if ((err = ecc_find_curve("P-384", &curve)) != CRYPT_OK) {
			//printf("Error finding P-384 curve: %s\n", error_to_string(err));
			return false;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P521) {
		if ((err = ecc_find_curve("P-521", &curve)) != CRYPT_OK) {
			//printf("Error finding P-521 curve: %s\n", error_to_string(err));
			return false;
		}
	}
	else {
		//printf("Invalid curve\n");
		return false;
	}


	mp_init(&x);
	mp_init(&y);

	// 將qx和qy從字串轉換為大數
	if ((err = mp_read_radix(&x, qx, 16)) != CRYPT_OK || (err = mp_read_radix(&y, qy, 16)) != CRYPT_OK) {
		//printf("Error reading qx and qy: %s\n", error_to_string(err));
		mp_clear_multi(&x, &y, NULL);
		return false;
	}

	// 檢查公鑰是否為無窮遠點
    if (mp_iszero(&x) && mp_iszero(&y)) {
       // printf("Public key is at infinity\n");
        mp_clear_multi(&x, &y, NULL);
        return false;
    }

	// 驗證公鑰: 利用公式 y^2 = x^3 + ax + b (mod p) 驗證公鑰是否在曲線上
	mp_int a,  b,  p,  lhs,  rhs;

	mp_init(&a);
	mp_init(&b);
	mp_init(&p);
	mp_init(&lhs);
	mp_init(&rhs);


	// 讀取曲線參數
	mp_read_radix(&a, curve->A, 16);
	mp_read_radix(&b, curve->B, 16);
	mp_read_radix(&p, curve->prime, 16);

	// 計算左側 y^2 (mod p)
	mp_sqr(&y, &lhs); // y^2
	mp_mod(&lhs, &p, &lhs); // y^2 (mod p)

	// 計算右側 x^3 + ax + b (mod p)
	mp_sqr(&x, &rhs); // x^2
	mp_mulmod(&rhs, &x, &p, &rhs); // x^3 (mod p)
	mp_mulmod(&a, &x, &p, &x); // ax (mod p)
	mp_addmod(&rhs, &x, &p, &rhs); // x^3 + ax (mod p)
	mp_addmod(&rhs, &b, &p, &rhs); // x^3 + ax + b (mod p)

	// 比較左側和右側
	if (mp_cmp(&lhs, &rhs) != LTC_MP_EQ) {
		//printf("Invalid public key\n");
		//mp_clear_multi(&x, &y, &a, &b, &p, &lhs, &rhs, NULL);
		mp_clear(&x);
		mp_clear(&y);
		mp_clear(&a);
		mp_clear(&b);
		mp_clear(&p);
		mp_clear(&lhs);
		mp_clear(&rhs);
		return false;
	}

	// 檢查公鑰是否在合理範圍內
	if (mp_cmp(&x, &p) != LTC_MP_LT || mp_cmp(&y, &p) != LTC_MP_LT || mp_cmp_d(&x, 0) != LTC_MP_GT || mp_cmp_d(&y, 0) != LTC_MP_GT) {
		//printf("Invalid public key: x or y out of range\n");
		mp_clear_multi(&x, &y, &a, &b, &p, &lhs, &rhs, NULL);
		return false;
	}

	mp_clear(&x);
	mp_clear(&y);
	mp_clear(&a);
	mp_clear(&b);
	mp_clear(&p);
	mp_clear(&lhs);
	mp_clear(&rhs);

	return true;
	
}

const int ECDSA_HASH_SHA2_256 = 1;
const int ECDSA_HASH_SHA2_384 = 2;
const int ECDSA_HASH_SHA2_512 = 3;
const int ECDSA_HASH_SHA3_256 = 4;
const int ECDSA_HASH_SHA3_384 = 5;
const int ECDSA_HASH_SHA3_512 = 6;
const int ECDSA_HASH_SHAKE128 = 7;
const int ECDSA_HASH_SHAKE256 = 8;




void hash_message(char* message, unsigned long messageLen, int hashAlgorithm, unsigned char* out, unsigned long* outlen) {
	int err;
	hash_state md;

	switch (hashAlgorithm) {
	case 1:  //ECDSA_HASH_SHA2_256
		sha256_init(&md);
		if ((err = sha256_process(&md, message, messageLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}

		if ((err = sha256_done(&md, out)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		*outlen = 256 / 8;
		break; 
	case 2: //ECDSA_HASH_SHA2_384
		sha384_init(&md);
		if ((err = sha384_process(&md, message, messageLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha384_done(&md, out)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		*outlen = 384 / 8;
		break;
	case 3: //ECDSA_HASH_SHA2_512
		sha512_init(&md);
		if ((err = sha512_process(&md, message, messageLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha512_done(&md, out)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		*outlen = 512 / 8;
		break;
	case 4: //ECDSA_HASH_SHA3_256
		sha3_256_init(&md);
		if ((err = sha3_process(&md, message, messageLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha3_done(&md, out)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		*outlen = 256 / 8;
		break;
	case 5: //ECDSA_HASH_SHA3_384
		sha3_384_init(&md);
		if ((err = sha3_process(&md, message, messageLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha3_done(&md, out)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		*outlen = 384 / 8;
		break;
	case 6: //ECDSA_HASH_SHA3_512
		sha3_512_init(&md);
		if ((err = sha3_process(&md, message, messageLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha3_done(&md, out)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		*outlen = 512 / 8;
		break;
	case 7: //ECDSA_HASH_SHAKE128
		//sha3_shake_init(&md,128);
		if ((err = sha3_shake_init(&md, 128)) != CRYPT_OK) {
			printf("Could not init SHAKE128 (%s)\n", error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = sha3_shake_process(&md, message, messageLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha3_shake_done(&md, out, 128/8)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		*outlen = 128 / 8;
		break;
	case 8: //ECDSA_HASH_SHAKE256
		sha3_shake_init(&md, 256);
		if ((err = sha3_shake_process(&md, message, messageLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha3_shake_done(&md, out, 256/8)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		*outlen = 256 / 8;
		break;

	default:
		printf("Unsupported hash algorithm\n");
		return;
	}

	
}

void ecdsaSignatureGenerate(int keypairCurve, int hashAlgorithm, char* d, char* message) {
	crypt_mp_init("ltm"); //使用libtommath
	
	int err;
	ecc_key key;
	prng_state prng;
	const ltc_ecc_curve* curve;
	//key的長度
	int keysize = (keypairCurve == ECDSA_CURVE_P256) ? 32 : (keypairCurve == ECDSA_CURVE_P384) ? 48 : (keypairCurve == ECDSA_CURVE_P521) ? 66 : 0;
	unsigned long outlen; // message digest的長度
	unsigned char out[256]; // message digest
	unsigned char hash[512 / 8]; // 計算出的hash (最大是512 bits)
	unsigned long hashlen; // hash的長度
	unsigned char* dBytes; // d的byte陣列
	unsigned long dBytesLen; // d的byte陣列的長度
	unsigned char* messageBytes; // message的byte陣列
	unsigned long messageBytesLen; // message的byte陣列的長度

	dBytes = (unsigned char*)malloc(strlen(d)/2);
	messageBytes = (unsigned char*)malloc(strlen(message) / 2);


	/* 把d轉成byte陣列 */
	hex_to_bytes(d, dBytes, &dBytesLen);
	/* 把message轉成byte陣列 */
	hex_to_bytes(message, messageBytes, &messageBytesLen);

	/* register yarrow */
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


	// 獲取P - 256曲線
	if (keypairCurve == ECDSA_CURVE_P256)
	{
		if ((err = ecc_find_curve("P-256", &curve)) != CRYPT_OK) {
			printf("Error finding P-256 curve: %s\n", error_to_string(err));
			return -1;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P384) // 獲取P - 384曲線
	{
		if ((err = ecc_find_curve("P-384", &curve)) != CRYPT_OK) {
			printf("Error finding P-384 curve: %s\n", error_to_string(err));
			return -1;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P521) // 獲取P - 521曲線
	{
		if ((err = ecc_find_curve("P-521", &curve)) != CRYPT_OK) {
			printf("Error finding P-521 curve: %s\n", error_to_string(err));
			return -1;
		}
	}
	else
	{
		printf("Error finding curve: %s\n", error_to_string(err));
		return -1;
	}


	/* 產生ECC key */
	if ((err = ecc_make_key_ex(&prng, find_prng("yarrow"), &key, curve)) != CRYPT_OK) {
		printf("Error generating ECC keypair: %s\n", error_to_string(err));
		return -1;
	}

	//直接把key裡面的private key設定為d (private key)
	ltc_mp.unsigned_read(key.k, dBytes, dBytesLen);


	/* 計算訊息的 hash */
	hash_message(messageBytes, messageBytesLen, hashAlgorithm, hash, &hashlen);

	printf("Hash: ");
	for (int i = 0; i < hashlen; i++)
	{
		printf("%02X", hash[i]);
	}
	printf("\n");

	/* 生成簽名 */
	if ((err = ecc_sign_hash(hash, hashlen, out, &outlen, &prng, find_prng("yarrow"), &key)) != CRYPT_OK) {
		printf("Error signing message, %s\n", error_to_string(err));
		return;
	}

	/* 輸出簽名 */
	unsigned char* sig = (unsigned char*)malloc(2 * outlen + 1);
	bytes_to_hex(out, outlen, sig);
	printf("Signature: %s\n", sig);
	

	/* 解碼簽名 */
	ltc_asn1_list sig_list[2];
	mp_int r, s;

	/* 初始化 r 和 s */
	if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) {
		printf("Error initializing r and s, %s\n", error_to_string(err));
		return;
	}

	/* 設定 ASN.1 列表 */
	sig_list[0].type = LTC_ASN1_INTEGER;
	sig_list[0].data = &r;
	sig_list[1].type = LTC_ASN1_INTEGER;
	sig_list[1].data = &s;

	/* 解碼簽名 */
	if ((err = der_decode_sequence(out, outlen, sig_list, 2)) != CRYPT_OK) {
		printf("Error decoding signature, %s\n", error_to_string(err));
		return;
	}

	/* 輸出 r 和 s */
	char r_str[512], s_str[512];
	mp_to_radix(&r, r_str, sizeof(r_str), NULL, 16);
	mp_to_radix(&s, s_str, sizeof(s_str), NULL, 16);
	printf("r: %s\n", r_str);
	printf("s: %s\n", s_str);

	/* 清理 */
	mp_clear_multi(&r, &s, NULL);

	/* 清理 */
	
	ecc_free(&key);
	free(messageBytes);
	free(dBytes);
	free(sig);
	sig = NULL;
}


int ecdsaSignatureVerify(int keypairCurve, int hashAlgorithm, char* qx, char* qy, char* r, char* s, char* message) {
	crypt_mp_init("ltm"); //使用libtommath

	int err;
	ecc_key key;
	prng_state prng;
	const ltc_ecc_curve* curve;
	//key的長度
	int keysize = (keypairCurve == ECDSA_CURVE_P256) ? 32 : (keypairCurve == ECDSA_CURVE_P384) ? 48 : (keypairCurve == ECDSA_CURVE_P521) ? 66 : 0;
	unsigned char hash[512 / 8]; // 計算出的hash (最大是512 bits)
	unsigned long hashlen; // hash的長度
	unsigned char* messageBytes; // message的byte陣列
	unsigned long messageBytesLen; // message的byte陣列的長度

	char* qxBytes = (char*)malloc(strlen(qx) / 2); // qx的byte陣列
	char* qyBytes = (char*)malloc(strlen(qy) / 2); // qy的byte陣列
	int qxBytesLen, qyBytesLen; // qx和qy的byte陣列的長度


	hex_to_bytes(qx, qxBytes, &qxBytesLen);
	hex_to_bytes(qy, qyBytes, &qyBytesLen);

	messageBytes = (unsigned char*)malloc(strlen(message) / 2);

	/*把r,s轉成mp_int*/
	mp_int r_mp_int, s_mp_int;
	mp_init_multi(&r_mp_int, &s_mp_int, NULL);

	mp_read_radix(&r_mp_int, r, 16);
	mp_read_radix(&s_mp_int, s, 16);

	/*嘗試利用r,s組回sig*/
	unsigned char sig[512];
	unsigned long siglen = sizeof(sig);

	

	/* 組合 r 和 s */
	ltc_asn1_list sig_list[2];
	sig_list[0].type = LTC_ASN1_INTEGER;
	sig_list[0].data = &r_mp_int;
	sig_list[1].type = LTC_ASN1_INTEGER;
	sig_list[1].data = &s_mp_int;
	/* 編碼簽名 */
	if ((err = der_encode_sequence(sig_list, 2, sig, &siglen)) != CRYPT_OK) {
		printf("Error encoding signature, %s\n", error_to_string(err));
		return 0;
	}

	/* 輸出簽名 */
	unsigned char* sig_hex = (unsigned char*)malloc(2 * siglen + 1);
	bytes_to_hex(sig, siglen, sig_hex);
	printf("Rwcovered Signature: %s\n", sig_hex);

	
	/* 把message轉成byte陣列 */
	hex_to_bytes(message, messageBytes, &messageBytesLen);

	/* register yarrow */
	if (register_prng(&yarrow_desc) == -1) {
		printf("Error registering Yarrow\n");
		return 0;
	}
	/* 設定PRNG */
	if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL))
		!= CRYPT_OK) {
		printf("Error setting up PRNG, %s\n", error_to_string(err));
		return 0;
	}


	// 獲取P - 256曲線
	if (keypairCurve == ECDSA_CURVE_P256)
	{
		if ((err = ecc_find_curve("P-256", &curve)) != CRYPT_OK) {
			printf("Error finding P-256 curve: %s\n", error_to_string(err));
			return 0;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P384) // 獲取P - 384曲線
	{
		if ((err = ecc_find_curve("P-384", &curve)) != CRYPT_OK) {
			printf("Error finding P-384 curve: %s\n", error_to_string(err));
			return 0;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P521) // 獲取P - 521曲線
	{
		if ((err = ecc_find_curve("P-521", &curve)) != CRYPT_OK) {
			printf("Error finding P-521 curve: %s\n", error_to_string(err));
			return 0;
		}
	}
	else
	{
		printf("Error finding curve: %s\n", error_to_string(err));
		return 0;
	}


	/* 產生ECC key */
	if ((err = ecc_make_key_ex(&prng, find_prng("yarrow"), &key, curve)) != CRYPT_OK) {
		printf("Error generating ECC keypair: %s\n", error_to_string(err));
		return 0;
	}

	//直接把key裡面的public key 設定為qx, qy
	ltc_mp.unsigned_read(key.pubkey.x, qxBytes, qxBytesLen);
	ltc_mp.unsigned_read(key.pubkey.y, qyBytes, qyBytesLen);

	/* 計算訊息的 hash */
	hash_message(messageBytes, messageBytesLen, hashAlgorithm, hash, &hashlen);

	printf("Hash: ");
	for (int i = 0; i < hashlen; i++)
	{
		printf("%02X", hash[i]);
	}
	printf("\n");

	/* 驗證簽名 */
	int verifyStatus;
	if ((err = ecc_verify_hash(sig, siglen, hash, hashlen,&verifyStatus, &key)) != CRYPT_OK) {
		printf("Error verifying signature, %s\n", error_to_string(err));
		return 0;
	}

	printf("Verify Status: %d\n", verifyStatus);

	/* 清理 */
	mp_clear_multi(&r_mp_int, &s_mp_int, NULL);
	free(sig_hex);
	free(qxBytes);
	free(qyBytes);
	free(messageBytes);
	ecc_free(&key);
	return verifyStatus;
	
}
