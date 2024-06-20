#include <tommath.h>
#include "stdio.h"
#include "string.h"
#include <tomcrypt.h>
#include "utils.h"


const int SHA2_256 = 1;
const int SHA2_384 = 2;
const int SHA2_512 = 3;
const int SHA3_256 = 4;
const int SHA3_384 = 5;
const int SHA3_512 = 6;

// SHA
void shaHash(const int hashAlgorithm, const char* message,  char* outHash, int* outHashLength) {

	unsigned char* messageBytes = malloc(strlen(message) / 2); //把message(字串)轉成bytes
	int messageBytesLen;
	hex_to_bytes(message, messageBytes, &messageBytesLen);

	int err;
	hash_state md;
	unsigned long hashLen;
	unsigned char hash[512 / 8]; // 計算出的hash (最大是512 bits)

	//初始化hash
	switch (hashAlgorithm)
	{
		case 1: // SHA2-256
			sha256_init(&md);
			if ((err = sha256_process(&md, messageBytes, messageBytesLen)) != CRYPT_OK) {
				printf("Error hashing message: %s\n", error_to_string(err));
				return;
			}

			if ((err = sha256_done(&md, hash)) != CRYPT_OK) {
				printf("Error finishing hash: %s\n", error_to_string(err));
				return;
			}
			hashLen = 256 / 8; // 256 bits
			break;
		case 2: // SHA2-384
			sha384_init(&md);
			if ((err = sha384_process(&md, messageBytes, messageBytesLen)) != CRYPT_OK) {
				printf("Error hashing message: %s\n", error_to_string(err));
				return;
			}

			if ((err = sha384_done(&md, hash)) != CRYPT_OK) {
				printf("Error finishing hash: %s\n", error_to_string(err));
				return;
			}
			hashLen = 384 / 8; // 384 bits
			break;
		case 3: // SHA2-512
			sha512_init(&md);
			if ((err = sha512_process(&md, messageBytes, messageBytesLen)) != CRYPT_OK) {
				printf("Error hashing message: %s\n", error_to_string(err));
				return;
			}

			if ((err = sha512_done(&md, hash)) != CRYPT_OK) {
				printf("Error finishing hash: %s\n", error_to_string(err));
				return;
			}
			hashLen = 512 / 8; // 512 bits
			break;
		case 4: // SHA3-256
			sha3_256_init(&md);
			if ((err = sha3_process(&md, messageBytes, messageBytesLen)) != CRYPT_OK) {
				printf("Error hashing message: %s\n", error_to_string(err));
				return;
			}
			if ((err = sha3_done(&md, hash)) != CRYPT_OK) {
				printf("Error finishing hash: %s\n", error_to_string(err));
				return;
			}
			hashLen = 256 / 8; // 256 bits
			break;
		case 5: // SHA3-384
			sha3_384_init(&md);
			if ((err = sha3_process(&md, messageBytes, messageBytesLen)) != CRYPT_OK) {
				printf("Error hashing message: %s\n", error_to_string(err));
				return;
			}
			if ((err = sha3_done(&md, hash)) != CRYPT_OK) {
				printf("Error finishing hash: %s\n", error_to_string(err));
				return;
			}
			hashLen = 384 / 8; // 384 bits
			break;
		case 6: // SHA3-512
			sha3_512_init(&md);
			if ((err = sha3_process(&md, messageBytes, messageBytesLen)) != CRYPT_OK) {
				printf("Error hashing message: %s\n", error_to_string(err));
				return;
			}
			if ((err = sha3_done(&md, hash)) != CRYPT_OK) {
				printf("Error finishing hash: %s\n", error_to_string(err));
				return;
			}
			hashLen = 512 / 8; // 512 bits
			break;
	default:
		break;
	}

	//輸出hash
	/*
	printf("SHA Hash: ");
	for (int i = 0; i < hashLen; i++)
	{
		printf("%02X", hash[i]);
	}
	printf("\n");
	*/

	//輸出hash
	bytes_to_hex(hash, hashLen, outHash);
	*outHashLength = hashLen * 2;
	

	//清理
	free(messageBytes);
	
}