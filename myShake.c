#include <tommath.h>
#include "stdio.h"
#include "string.h"
#include <tomcrypt.h>
#include "utils.h"


const int SHAKE_128 = 1;
const int SHAKE_256 = 2;


// SHAKE
void shakeHash(const int hashAlgorithm, const char* message, int outHashLength, char* outHash) {

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
	case 1: // SHAKE-128
		if ((err = sha3_shake_init(&md, 128)) != CRYPT_OK) {
			printf("Could not init SHAKE128 (%s)\n", error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = sha3_shake_process(&md, messageBytes, messageBytesLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha3_shake_done(&md, hash, outHashLength/8)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		break;
	case 2: // SHAKE-256
		if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) {
			printf("Could not init SHAKE256 (%s)\n", error_to_string(err));
			return EXIT_FAILURE;
		}
		if ((err = sha3_shake_process(&md, messageBytes, messageBytesLen)) != CRYPT_OK) {
			printf("Error hashing message: %s\n", error_to_string(err));
			return;
		}
		if ((err = sha3_shake_done(&md, hash, outHashLength/8)) != CRYPT_OK) {
			printf("Error finishing hash: %s\n", error_to_string(err));
			return;
		}
		break;
	
	default:
		break;
	}

	

	//輸出hash
	bytes_to_hex(hash, outHashLength/8, outHash);

	//清理
	free(messageBytes);

}