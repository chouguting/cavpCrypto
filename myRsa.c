#include <tommath.h>
#include "stdio.h"
#include <stdlib.h>
#include "string.h"
#include <tomcrypt.h>
#include "mySha.h"
#include "myEcdsa.h"
#include "utils.h"

void computeAProbablePrimeFactorBasedOnAuxiliaryPrimes(
	mp_int* prime_out,
	mp_int* r1,
	mp_int* r2,
	mp_int* x,
	mp_int* e
) {

	mp_int twoR1;
	mp_int inverseOfR2Mod2R1;
	mp_int inverseOf2R1ModR2;
	mp_int r;
	mp_int twoR1R2;
	mp_int yMinus1;
	mp_int gcd;
	mp_int loopCounter;

	bool isPrime;
	char loopResult[1025];
	char gcdResult[1025];
	char yMinusOneResult[1025];
	char primeOutResult[1025];


	//r =  ((r2^(-1) mod (2*r1)) * r2) – (((2*r1)^(–1) mod r2) * (2*r1))
	//calculate the modular inverse of 2*r1(mod r2) and r2(mod 2*r1) first


	mp_init(&twoR1);
	mp_mul_2(r1, &twoR1); 	//twoR1 = 2*r1

	mp_init(&inverseOfR2Mod2R1);
	mp_invmod(r2, &twoR1, &inverseOfR2Mod2R1); 	//inverseOfR2Mod2R1 = r2^(-1) mod (2*r1)


	mp_init(&inverseOf2R1ModR2);
	mp_invmod(&twoR1, r2, &inverseOf2R1ModR2); //inverseOf2R1ModR2 = (2*r1)^(–1) mod r2

	//r =  ((r2^(-1) mod (2*r1)) * r2) – (((2*r1)^(–1) mod r2) * (2*r1))
	mp_init(&r);
	mp_copy(r2, &r);
	mp_mul(&r, &inverseOfR2Mod2R1, &r);
	mp_mul(&twoR1, &inverseOf2R1ModR2, &twoR1);
	mp_sub(&r, &twoR1, &r);
	mp_clear(&twoR1);
	mp_clear(&inverseOfR2Mod2R1);
	mp_clear(&inverseOf2R1ModR2);

	//y = x + ((r – x) mod (2*r1*r2))
	//prime_out = y = x + ((r – x) mod (2*r1*r2))
	mp_init(&twoR1R2);
	mp_mul(r1, r2, &twoR1R2);
	mp_mul_2(&twoR1R2, &twoR1R2);
	mp_sub(&r, x, &r);
	mp_mod(&r, &twoR1R2, prime_out);
	mp_add(prime_out, x, prime_out);
	mp_clear(&r);


	//regenerate y until (GCD(Y–1, e) = 1) and y is a probable prime
	//if (GCD(Y–1, e) = 1) and y is a probable prime, then return y
	mp_init(&yMinus1);
	mp_sub_d(prime_out, 1, &yMinus1); //yMinus1 = y - 1 = prime_out - 1
	mp_init(&gcd);
	mp_gcd(&yMinus1, e, &gcd); //gcd = GCD(Y–1, e)

	mp_prime_is_prime(prime_out, 100, &isPrime);

	// loop counter
	mp_init(&loopCounter);
	mp_set(&loopCounter, 0);

	mp_to_radix(&gcd, gcdResult, sizeof(gcdResult), NULL, 10);
	mp_to_radix(&yMinus1, yMinusOneResult, sizeof(yMinusOneResult), NULL, 10);
	mp_to_radix(prime_out, primeOutResult, sizeof(primeOutResult), NULL, 10);

	//printf("GCD(Y–1, e) before loop: %s\n", gcdResult);
	//printf("Y–1 before loop: %s\n", yMinusOneResult);
	//printf("prime_out before loop: %s\n", primeOutResult);

	while (mp_cmp_d(&gcd, 1) != MP_EQ || !isPrime) {
		mp_add_d(&loopCounter, 1, &loopCounter);
		mp_add(prime_out, &twoR1R2, prime_out); //y = y + 2*r1*r2 (prime_out = prime_out + 2*r1*r2)
		mp_sub_d(prime_out, 1, &yMinus1); //yMinus1 = y - 1
		mp_gcd(&yMinus1, e, &gcd); //gcd = GCD(Y–1, e)
		mp_prime_is_prime(prime_out, 1, &isPrime); //check if y is a probable prime

		mp_to_radix(&yMinus1, yMinusOneResult, sizeof(yMinusOneResult), NULL, 10);
		mp_to_radix(&loopCounter, loopResult, sizeof(loopResult), NULL, 10);
		mp_to_radix(&gcd, gcdResult, sizeof(gcdResult), NULL, 10);
		mp_to_radix(prime_out, primeOutResult, sizeof(primeOutResult), NULL, 10);


		//printf("Loop: %s, GCD(Y–1, e): %s\n", loopResult, gcdResult);
		//printf("Y–1: %s\n", yMinusOneResult);
		//printf("y: %s\n\n", primeOutResult);

	}

	// print number of loops
	mp_to_radix(&loopCounter, loopResult, sizeof(loopResult), NULL, 10);
	//printf("Tatal Number of loops: %s\n\n\n", loopResult);

	mp_clear(&yMinus1);
	mp_clear(&gcd);
	mp_clear(&twoR1R2);

}


void generateKeyPairBasedOnAuxiliaryProbablePrimes(
	mp_int* p_out,
	mp_int* q_out,
	mp_int* n_out,
	mp_int* d_out,
	mp_int* xP1,
	mp_int* xP2,
	mp_int* xP,
	mp_int* xQ1,
	mp_int* xQ2,
	mp_int* xQ,
	mp_int* e
) {

	mp_int pMinus1;
	mp_int qMinus1;
	mp_int lcm;
	char xP1Next[1025];
	char xP2Next[1025];


	//Based on FIPS 186-4,
	// Appendix B.3.6 Generation of Probable Primes with Conditions Based on Auxiliary Probable Primes
	//find next prime from xP1
	mp_prime_next_prime(xP1, 100, NULL);

	mp_to_radix(xP1, xP1Next, sizeof(xP1Next), NULL, 16);
	//printf("next xP1: %s\n", xP1Next);

	//find next prime from xP2
	mp_prime_next_prime(xP2, 100, NULL);

	mp_to_radix(xP2, xP2Next, sizeof(xP2Next), NULL, 16);
	//printf("next xP2: %s\n", xP2Next);

	//helper function to compute a probable prime factor based on auxiliary primes
	computeAProbablePrimeFactorBasedOnAuxiliaryPrimes(p_out, xP1, xP2, xP, e);

	//find next prime from xQ1
	mp_prime_next_prime(xQ1, 100, NULL);
	//find next prime from xQ2
	mp_prime_next_prime(xQ2, 100, NULL);
	//helper function to compute a probable prime factor based on auxiliary primes
	computeAProbablePrimeFactorBasedOnAuxiliaryPrimes(q_out, xQ1, xQ2, xQ, e);

	//n = p * q
	mp_mul(p_out, q_out, n_out);

	//calculate lcm(p-1, q-1)
	mp_init(&pMinus1);
	mp_sub_d(p_out, 1, &pMinus1);
	mp_init(&qMinus1);
	mp_sub_d(q_out, 1, &qMinus1);
	mp_init(&lcm);
	mp_lcm(&pMinus1, &qMinus1, &lcm);
	mp_clear(&pMinus1);
	mp_clear(&qMinus1);

	//d = e^(-1) mod lcm(p-1, q-1)
	mp_invmod(e, &lcm, d_out);
	mp_clear(&lcm);
}
mp_int xP1;
mp_int xP2;
mp_int xP;
mp_int xQ1;
mp_int xQ2;
mp_int xQ;
mp_int e;
mp_int p;
mp_int q;
mp_int n;
mp_int d;

mp_int dP;
mp_int dQ;
mp_int qP;

rsa_key rsaKeyPair()
{
	char xP1Hex[1025];
	char xP2Hex[1025];
	char xPHex[1025];

	char xQ1Hex[1025];
	char xQ2Hex[1025];
	char xQHex[1025];
	char pHex[1025];
	char qHex[1025];
	char nHex[1025];
	char dHex[1025];
	char eHex[1025];

	rsa_key key;
	//support RSA 4096
	//each byte is 2 hex characters
	//maximum 4096 bits, which is 512 bytes, so we need 1025 hex characters to store the number (with null terminator)

	bool result;

	mp_init(&xP1);
	mp_init(&xP2);
	mp_init(&xP);
	mp_init(&xQ1);
	mp_init(&xQ2);
	mp_init(&xQ);
	mp_init(&e);
	mp_init(&p);
	mp_init(&q);
	mp_init(&n);
	mp_init(&d);

	for (int i = 0; i < 1; i++) {

		strcpy_s(xP1Hex, sizeof(xP1Hex), "0267A8B7429FBBAB3EF24B794E83BB70D9AB3A6DA947EA3585D00CBB7F152FD955A9AEF0DCAFFFCA1F32536F85D1");
		strcpy_s(xP2Hex, sizeof(xP2Hex), "016DFB2C9836206B7BF416BE81B7838DCD8D6CFFD3D63D8EDC5B2A356CD6548FB2890B844F4CB64C9A045DB724AE29");
		strcpy_s(xPHex, sizeof(xPHex), "B83E9CF3F6FFFDD4FF4064E7BCB3543DAEC3C0D7D478E61530A5E5D9FC5C3907B4D18E8385D0E6D70656396C31109CB6C4609D8B7BBF1E5A31F95E7773F11D499150EE9028F9A9D4D59DDD4F5EB2F0979B2107FF1EE767B524FC8747CF42FAD15A5C9BB63449D6DD2628EF9D7E75C8D1BFA619F117F7BEE22D0E3B5CDC254F58");
		strcpy_s(xQ1Hex, sizeof(xQ1Hex), "0C8E2CE779C64B5BA7A1CA52557A3FC9E5D70A4937F1AC2114B21E37");
		strcpy_s(xQ2Hex, sizeof(xQ2Hex), "01AEBB2E8EC1EC20414B7CB2F371156A526D96BA264E2B0407A1");
		strcpy_s(xQHex, sizeof(xQHex), "D5947A88546E55696B8D1B9FBDE08C23AB8A8E745BCAEE040D83CECA652E640B020B85B4BC746F1D21131ED39C8FC2603F229949890497EDB80D975D27626E9C457226B700AC51CD5A78BE4F4441F3AC5CBD69B944C68D3985CA6A266A501BCD17299223C8311CB9A1488DD0494F2B3BB27A0CC68605DE8BBCD94A7A694A677B");
		strcpy_s(eHex, sizeof(eHex), "057909487D");


		mp_read_radix(&xP1, xP1Hex, 16);
		mp_read_radix(&xP2, xP2Hex, 16);
		mp_read_radix(&xP, xPHex, 16);
		mp_read_radix(&xQ1, xQ1Hex, 16);
		mp_read_radix(&xQ2, xQ2Hex, 16);
		mp_read_radix(&xQ, xQHex, 16);
		mp_read_radix(&e, eHex, 16);


		//generate key pair
		generateKeyPairBasedOnAuxiliaryProbablePrimes(&p, &q, &n, &d, &xP1, &xP2, &xP, &xQ1, &xQ2, &xQ, &e);

		//convert to hex
		mp_to_radix(&p, pHex, sizeof(pHex), NULL, 16);
		mp_to_radix(&q, qHex, sizeof(qHex), NULL, 16);
		mp_to_radix(&n, nHex, sizeof(nHex), NULL, 16);
		mp_to_radix(&d, dHex, sizeof(dHex), NULL, 16);
		mp_to_radix(&e, eHex, sizeof(eHex), NULL, 16);

	}
	//return this key with the previous calculation
	key.type = PK_PRIVATE;
	key.e = (mp_int*)&e;
	key.d = (mp_int*)&d;
	key.N = (mp_int*)&n;
	key.p = (mp_int*)&p;
	key.q = (mp_int*)&q;
	
	//to calculate CRT parameters
	//calculate dP
	mp_int tmp;
	mp_init(&tmp);
	mp_sub_d(&p, 1, &tmp);	//tmp = p-1
	mp_init(&dP);
	mp_mod(&d, &tmp, &dP);	//dP = d mod (p-1)
	key.dP = (mp_int*)&dP;
	
	//calculate dQ
	mp_init(&dQ);
	mp_sub_d(&q, 1, &tmp);	//tmp = q-1
	mp_mod(&d, &tmp, &dQ);	//dQ = d mod (q-1)
	key.dQ = (mp_int*)&dQ;

	//calculate qInv
	mp_init(&qP);
	mp_invmod(&q, &p, &qP);	// qP = qInverse = q^(-1) mod p
	key.qP = (mp_int*)&qP;
	return key;
}

const int RSA_SHA2_256 = 1;
const int RSA_SHA2_384 = 2;
const int RSA_SHA2_512 = 3;
const int RSA_SHA3_256 = 4;
const int RSA_SHA3_384 = 5;
const int RSA_SHA3_512 = 6;
char hex_signature[4096];

// rsaSignMessage_pkcs1_v1_5
char* rsaSignMessage_pkcs1_v1_5(const char* message, const int hashAlgo) {
	//generate rsaKey
	crypt_mp_init("ltm");
	rsa_key key = rsaKeyPair();
	//print key.e and key.n and key.d
	//char e_str[1024], n_str[1024], d_str[1024];
	//mp_to_radix(key.e, e_str, sizeof(e_str), NULL, 16);
	//mp_to_radix(key.N, n_str, sizeof(n_str), NULL, 16);
	//mp_to_radix(key.d, d_str, sizeof(d_str), NULL, 16);
	//printf("e: %s\n", e_str);
	//printf("n: %s\n", n_str);
	//printf("d: %s\n", d_str);

	unsigned char sig[1024];
	unsigned long siglen = sizeof(sig);
	int err;
	unsigned char hash[1024];
	unsigned long hashlen;

	//register hash
	if (register_hash(&sha256_desc) == -1) {
		printf("Error registering SHA-256.\n");
		return -1;
	}
	if (register_hash(&sha384_desc) == -1) {
		printf("Error registering SHA-384.\n");
		return -1;
	}
	if (register_hash(&sha512_desc) == -1) {
		printf("Error registering SHA-512.\n");
		return -1;
	}
	if (register_hash(&sha3_256_desc) == -1) {
		printf("Error registering SHA3-256.\n");
		return -1;
	}
	if (register_hash(&sha3_384_desc) == -1) {
		printf("Error registering SHA3-384.\n");
		return -1;
	}
	if (register_hash(&sha3_512_desc) == -1) {
		printf("Error registering SHA3-512.\n");
		return -1;
	}
	//hash index
	int hash_idx = 0;
	//hash the message
	switch (hashAlgo) {
	case 1:
		shaHash(SHA2_256, message, hash, &hashlen);
		hash_idx = find_hash("sha256");
		break;
	case 2:
		shaHash(SHA2_384, message, hash, &hashlen);
		hash_idx = find_hash("sha384");
		break;
	case 3:
		shaHash(SHA2_512, message, hash, &hashlen);
		hash_idx = find_hash("sha512");
		break;
	case 4:
		shaHash(SHA3_256, message, hash, &hashlen);
		hash_idx = find_hash("sha3-256");
		break;
	case 5:
		shaHash(SHA3_384, message, hash, &hashlen);
		hash_idx = find_hash("sha3-384");
		break;
	case 6:
		shaHash(SHA3_512, message, hash, &hashlen);
		hash_idx = find_hash("sha3-512");
		break;
	default:
		printf("Invalid hash algorithm\n");
		return NULL;
	}

	//convert hash from hex to bytes
	unsigned char hash_byte[512 / 8];
	unsigned long hash_byte_len;
	hex_to_bytes(hash, hash_byte, &hash_byte_len);

	//sign the hash
	if ((err = rsa_sign_hash_ex(hash_byte, hash_byte_len, sig, &siglen, LTC_PKCS_1_V1_5, NULL, -1, hash_idx, 0, &key)) != CRYPT_OK) {
		printf("Error signing hash: %s\n", error_to_string(err));
		return -1;
	}

	printf("Signature generated successfully.\n");
	// 簽名成功，將簽名轉換為十六進制字符串
	// 為十六進制字符串分配兩倍於簽名長度的空間
	for (unsigned long i = 0; i < siglen; i++) {
		sprintf_s(hex_signature + i * 2, sizeof(hex_signature) - i * 2, "%02X", sig[i]);
	}
	hex_signature[siglen * 2] = '\0'; // 確保字符串以空字符結尾
	//printf("Signature: %s\n", hex_signature);
	return hex_signature;
	// Free the RSA key
	rsa_free(&key);
}

// rsaSignMessage_pss
char* rsaSignMessage_pss(const char* message, const int hashAlgo) {
	//generate rsaKey
	crypt_mp_init("ltm");
	rsa_key key = rsaKeyPair();

	unsigned char sig[1024];
	unsigned long siglen = sizeof(sig);
	int err;
	unsigned char hash[1024];
	unsigned long hashlen;

	//register hash
	if (register_hash(&sha256_desc) == -1) {
		printf("Error registering SHA-256.\n");
		return -1;
	}
	if (register_hash(&sha384_desc) == -1) {
		printf("Error registering SHA-384.\n");
		return -1;
	}
	if (register_hash(&sha512_desc) == -1) {
		printf("Error registering SHA-512.\n");
		return -1;
	}
	if (register_hash(&sha3_256_desc) == -1) {
		printf("Error registering SHA3-256.\n");
		return -1;
	}
	if (register_hash(&sha3_384_desc) == -1) {
		printf("Error registering SHA3-384.\n");
		return -1;
	}
	if (register_hash(&sha3_512_desc) == -1) {
		printf("Error registering SHA3-512.\n");
		return -1;
	}
	//hash index
	int hash_idx = 0;
	//hash the message
	switch (hashAlgo) {
	case 1:
		shaHash(SHA2_256, message, hash, &hashlen);
		hash_idx = find_hash("sha256");
		break;
	case 2:
		shaHash(SHA2_384, message, hash, &hashlen);
		hash_idx = find_hash("sha384");
		break;
	case 3:
		shaHash(SHA2_512, message, hash, &hashlen);
		hash_idx = find_hash("sha512");
		break;
	case 4:
		shaHash(SHA3_256, message, hash, &hashlen);
		hash_idx = find_hash("sha3-256");
		break;
	case 5:
		shaHash(SHA3_384, message, hash, &hashlen);
		hash_idx = find_hash("sha3-384");
		break;
	case 6:
		shaHash(SHA3_512, message, hash, &hashlen);
		hash_idx = find_hash("sha3-512");
		break;
	default:
		printf("Invalid hash algorithm\n");
		return NULL;
	}

	//convert hash from hex to bytes
	unsigned char hash_byte[512 / 8];
	unsigned long hash_byte_len;
	hex_to_bytes(hash, hash_byte, &hash_byte_len);

	//register prng
	if (register_prng(&yarrow_desc) == -1) {
		printf("Error registering PRNG.\n");
		return -1;
	}
	//make a prng
	prng_state prng;
	if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
		printf("Error making PRNG: %s\n", error_to_string(err));
		return -1;
	}

	//sign the hash
	if ((err = rsa_sign_hash_ex(hash_byte, hash_byte_len, sig, &siglen, LTC_PKCS_1_PSS, &prng, find_prng("yarrow"), hash_idx, 0, &key)) != CRYPT_OK) {
		printf("Error signing hash: %s\n", error_to_string(err));
		return -1;
	}

	printf("Signature generated successfully.\n");
	// 簽名成功，將簽名轉換為十六進制字符串
	// 為十六進制字符串分配兩倍於簽名長度的空間
	for (unsigned long i = 0; i < siglen; i++) {
		sprintf_s(hex_signature + i * 2, sizeof(hex_signature) - i * 2, "%02X", sig[i]);
	}
	hex_signature[siglen * 2] = '\0'; // 確保字符串以空字符結尾
	//printf("Signature: %s\n", hex_signature);
	return hex_signature;
	// Free the RSA key
	rsa_free(&key);
}

// rsaVerifyMessage_pkcs1_v1_5
int rsaVerifyMessage_pkcs1_v1_5(const char* message, const char* signature, const int hashAlgo, rsa_key* key) {
	crypt_mp_init("ltm");
	printf("message: %s\n", message);
	printf("signature: %s\n", signature);
	//print key.e and key.n and key.d
	char e_str[1024], n_str[1024], d_str[1024];
	mp_to_radix(key->e, e_str, sizeof(e_str), NULL, 16);
	mp_to_radix(key->N, n_str, sizeof(n_str), NULL, 16);
	mp_to_radix(key->d, d_str, sizeof(d_str), NULL, 16);

	//convert signature from hex to bytes
	unsigned char sig[1024];
	unsigned long siglen;
	hex_to_bytes(signature, sig, &siglen);
	unsigned char* hash[512];
	unsigned long hashlen;

	//register hash
	if (register_hash(&sha256_desc) == -1) {
		printf("Error registering SHA-256.\n");
		return -1;
	}
	if (register_hash(&sha384_desc) == -1) {
		printf("Error registering SHA-384.\n");
		return -1;
	}
	if (register_hash(&sha512_desc) == -1) {
		printf("Error registering SHA-512.\n");
		return -1;
	}
	if (register_hash(&sha3_256_desc) == -1) {
		printf("Error registering SHA3-256.\n");
		return -1;
	}
	if (register_hash(&sha3_384_desc) == -1) {
		printf("Error registering SHA3-384.\n");
		return -1;
	}
	if (register_hash(&sha3_512_desc) == -1) {
		printf("Error registering SHA3-512.\n");
		return -1;
	}
	//hash index
	int hash_idx = 0;
	//hash the message
	switch (hashAlgo) {
	case 1:
		shaHash(SHA2_256, message, hash, &hashlen);
		hash_idx = find_hash("sha256");
		break;
	case 2:
		shaHash(SHA2_384, message, hash, &hashlen);
		hash_idx = find_hash("sha384");
		break;
	case 3:
		shaHash(SHA2_512, message, hash, &hashlen);
		hash_idx = find_hash("sha512");
		break;
	case 4:
		shaHash(SHA3_256, message, hash, &hashlen);
		hash_idx = find_hash("sha3-256");
		break;
	case 5:
		shaHash(SHA3_384, message, hash, &hashlen);
		hash_idx = find_hash("sha3-384");
		break;
	case 6:
		shaHash(SHA3_512, message, hash, &hashlen);
		hash_idx = find_hash("sha3-512");
		break;
	default:
		printf("Invalid hash algorithm\n");
		return NULL;
	}
	//print the hash
	printf("Hash: %s\n", hash);

	//convert hash from hex to bytes
	unsigned char hash_byte[512 / 8];
	unsigned long hash_byte_len;
	hex_to_bytes(hash, hash_byte, &hash_byte_len);
	
	//key->type = PK_PUBLIC;

	//verify signature

	int stat;
	int err;
	if ((err = rsa_verify_hash_ex(sig, siglen, hash_byte, hash_byte_len, LTC_PKCS_1_V1_5, hash_idx, 0, &stat, key)) != CRYPT_OK) {
		printf("Error verifying signature: %s\n", error_to_string(err));
		return -1;
	}
	if (stat == 1) {
		printf("Signature is valid.\n");
		return 1;
	}
	else {
		printf("Signature is invalid.\n");
		return 0;
	}
}

// rsaVerifyMessage_pss
int rsaVerifyMessage_pss(const char* message, const char* signature, const int hashAlgo, rsa_key* key) {
	crypt_mp_init("ltm");
	printf("message: %s\n", message);
	printf("signature: %s\n", signature);

	//convert signature from hex to bytes
	unsigned char sig[1024];
	unsigned long siglen;
	hex_to_bytes(signature, sig, &siglen);
	unsigned char* hash[512];
	unsigned long hashlen;

	//register hash
	if (register_hash(&sha256_desc) == -1) {
		printf("Error registering SHA-256.\n");
		return -1;
	}
	if (register_hash(&sha384_desc) == -1) {
		printf("Error registering SHA-384.\n");
		return -1;
	}
	if (register_hash(&sha512_desc) == -1) {
		printf("Error registering SHA-512.\n");
		return -1;
	}
	if (register_hash(&sha3_256_desc) == -1) {
		printf("Error registering SHA3-256.\n");
		return -1;
	}
	if (register_hash(&sha3_384_desc) == -1) {
		printf("Error registering SHA3-384.\n");
		return -1;
	}
	if (register_hash(&sha3_512_desc) == -1) {
		printf("Error registering SHA3-512.\n");
		return -1;
	}
	//hash index
	int hash_idx = 0;
	//hash the message
	switch (hashAlgo) {
	case 1:
		shaHash(SHA2_256, message, hash, &hashlen);
		hash_idx = find_hash("sha256");
		break;
	case 2:
		shaHash(SHA2_384, message, hash, &hashlen);
		hash_idx = find_hash("sha384");
		break;
	case 3:
		shaHash(SHA2_512, message, hash, &hashlen);
		hash_idx = find_hash("sha512");
		break;
	case 4:
		shaHash(SHA3_256, message, hash, &hashlen);
		hash_idx = find_hash("sha3-256");
		break;
	case 5:
		shaHash(SHA3_384, message, hash, &hashlen);
		hash_idx = find_hash("sha3-384");
		break;
	case 6:
		shaHash(SHA3_512, message, hash, &hashlen);
		hash_idx = find_hash("sha3-512");
		break;
	default:
		printf("Invalid hash algorithm\n");
		return NULL;
	}
	//print the hash
	printf("Hash: %s\n", hash);

	//convert hash from hex to bytes
	unsigned char hash_byte[512 / 8];
	unsigned long hash_byte_len;
	hex_to_bytes(hash, hash_byte, &hash_byte_len);

	//key->type = PK_PUBLIC;

	//verify signature

	int stat;
	int err;
	if ((err = rsa_verify_hash_ex(sig, siglen, hash_byte, hash_byte_len, LTC_PKCS_1_PSS, hash_idx, 0, &stat, key)) != CRYPT_OK) {
		printf("Error verifying signature: %s\n", error_to_string(err));
		return -1;
	}
	if (stat == 1) {
		printf("Signature is valid.\n");
		return 1;
	}
	else {
		printf("Signature is invalid.\n");
		return 0;
	}
}