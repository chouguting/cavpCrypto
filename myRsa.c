#include <tommath.h>
#include "stdio.h"
#include <stdlib.h>
#include "string.h"
#include "mySha.h"
#include <tomcrypt.h>

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

	printf("GCD(Y–1, e) before loop: %s\n", gcdResult);
	printf("Y–1 before loop: %s\n", yMinusOneResult);
	printf("prime_out before loop: %s\n", primeOutResult);

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


		printf("Loop: %s, GCD(Y–1, e): %s\n", loopResult, gcdResult);
		//printf("Y–1: %s\n", yMinusOneResult);
		printf("y: %s\n\n", primeOutResult);

	}

	// print number of loops
	mp_to_radix(&loopCounter, loopResult, sizeof(loopResult), NULL, 10);
	printf("Tatal Number of loops: %s\n\n\n", loopResult);

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
	printf("next xP1: %s\n", xP1Next);

	//find next prime from xP2
	mp_prime_next_prime(xP2, 100, NULL);

	mp_to_radix(xP2, xP2Next, sizeof(xP2Next), NULL, 16);
	printf("next xP2: %s\n", xP2Next);

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


void rsaKeyPair()
{
	//support RSA 4096
	//each byte is 2 hex characters
	//maximum 4096 bits, which is 512 bytes, so we need 1025 hex characters to store the number (with null terminator)
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

	bool result;

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

		//print out the result
		printf("p: %s\n", pHex);
		printf("q: %s\n", qHex);
		printf("n: %s\n", nHex);
		printf("e: %s\n", eHex);
		printf("d: %s\n", dHex);

	}
	mp_clear(&xP1);
	mp_clear(&xP2);
	mp_clear(&xP);
	mp_clear(&xQ1);
	mp_clear(&xQ2);
	mp_clear(&xQ);
	mp_clear(&e);
	mp_clear(&p);
	mp_clear(&q);
	mp_clear(&n);
	mp_clear(&d);
	return 0;
}

mp_int* rsaSignMsg(mp_int privateKey_d, const char* message, const int hashAlgo) {
	unsigned char hash[512 / 8];
	mp_int* signature = malloc(sizeof(mp_int));
	int err;

	// Hash the message using SHA-256
	char shaHashResult[(512 / 8) * 2 + 1];
	int shaHashResultLen;
	shaHash(hashAlgo, message, shaHashResult, &shaHashResultLen);
	mp_read_radix(&signature, shaHashResult, 16);

	// Allocate memory for the signature
	/*signature = (unsigned char*)malloc(MAX_RSA_SIZE);
	if (signature == NULL) {
		perror("Failed to allocate memory for signature");
		exit(1);
	}*/

	// Sign the hash with the RSA private key
	if ((err = rsa_sign_hash_ex(hash, 32, signature, sig_len, LTC_PKCS_1_V1_5, NULL, 0, NULL, find_hash(hashAlgo), 0, privateKey_d)) != CRYPT_OK) {
		handleError(err);
	}

	return signature;
}


