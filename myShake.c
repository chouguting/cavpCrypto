#define _CRT_SECURE_NO_WARNINGS
#include <tommath.h>
#include "stdio.h"
#include "string.h"
#include <tomcrypt.h>
#include "utils.h"
#include <math.h>

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
	//unsigned char hash[512 / 8]; // 計算出的hash (最大是512 bits)
	unsigned char* hash = malloc(outHashLength / 8); 


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
	free(hash);

}


void shakeMCTHash(const int hashAlgorithm, const char* initialSeedString, int maxOutBitLength, int minOutBitLength) {
	int maxOutByteLength = floor((maxOutBitLength * 1.0) / 8);
	int minOutByteLength = ceil((minOutBitLength * 1.0) / 8);
	int byteLengthRange = maxOutByteLength - minOutByteLength + 1;
	char* outputHex = malloc(maxOutByteLength * 2 + 1); //maxOutByteLength*2+1
	strcpy(outputHex, initialSeedString);
	
	int currentOutByteLength = maxOutByteLength;


	for (int i = 0; i < 100; i++) {
		for (int j = 0; j < 1000; j++) {
			char leftMost16BytesOfOutputHex[33]; //16*2+1 = 33
			//copy 128 bits of outputHex to lastMost16Bytes
			//128 bits = 16 bytes = 32 characters, so copy 32 characters, 
			// and don't forget the end of string character '\0'
			strncpy(leftMost16BytesOfOutputHex, outputHex, 32); //copy 32 characters
			if (strlen(leftMost16BytesOfOutputHex) < 32) { //if the length of leftMost16BytesOfOutputHex is less than 32
				for (int k = strlen(leftMost16BytesOfOutputHex); k < 32; k++){
					leftMost16BytesOfOutputHex[k] = '0'; //fill with 0
				}
			}

			leftMost16BytesOfOutputHex[32] = '\0'; //end of string

			shakeHash(hashAlgorithm, leftMost16BytesOfOutputHex, currentOutByteLength * 8, outputHex);

			char rightMost2BytesOfOutputHex[5]; //2*2+1 = 5
			getIthByteInHex(outputHex, currentOutByteLength - 2, rightMost2BytesOfOutputHex);
			getIthByteInHex(outputHex, currentOutByteLength - 1, rightMost2BytesOfOutputHex + 2);
			int numberOfRightMost2Bytes = hexStringToInteger(rightMost2BytesOfOutputHex);
			
			
			if (j == 999) {
				printf("round: %d\n", i);
				printf("hash length: %d\n", currentOutByteLength*8);
				printf("hash: %s\n\n\n", outputHex);
			}
			currentOutByteLength = minOutByteLength + numberOfRightMost2Bytes % byteLengthRange;




		}
	}

	free(outputHex);
}