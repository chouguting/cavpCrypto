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

	unsigned char* messageBytes = malloc(strlen(message) / 2); //��message(�r��)�নbytes
	int messageBytesLen;
	hex_to_bytes(message, messageBytes, &messageBytesLen);

	int err;
	hash_state md;
	unsigned long hashLen;
	unsigned char hash[512 / 8]; // �p��X��hash (�̤j�O512 bits)

	//��l��hash
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

	//��Xhash
	/*
	printf("SHA Hash: ");
	for (int i = 0; i < hashLen; i++)
	{
		printf("%02X", hash[i]);
	}
	printf("\n");
	*/

	//��Xhash
	bytes_to_hex(hash, hashLen, outHash);
	*outHashLength = hashLen * 2;
	

	//�M�z
	free(messageBytes);
	
}


// MCT: monte carlo test
void sha2MCTHash(const int hashAlgorithm, const char* initialSeedString) {

	hash_state md;
	int err;
	unsigned char* seedBytes = malloc(strlen(initialSeedString) / 2); //��message(�r��)�নbytes
	int seedBytesLength;
	hex_to_bytes(initialSeedString, seedBytes, &seedBytesLength);


	for (int i = 0; i < 100; i++) {

		char lastLastLastHashBytes[512 / 8]; // �W�W�W����hash (�̤j�O512 bits)
		unsigned long lastLastLastHashBytesLength = seedBytesLength;
		copy_bytes(seedBytes, lastLastLastHashBytes, lastLastLastHashBytesLength); // ��seedBytes�ƻs��lastLastLastHashBytes

		char lastLastHashBytes[512 / 8]; // �W�W����hash (�̤j�O512 bits)
		unsigned long lastLastHashBytesLength = seedBytesLength;
		copy_bytes(seedBytes, lastLastHashBytes, lastLastHashBytesLength); // ��seedBytes�ƻs��lastLastHashBytes

		char lastHashBytes[512 / 8]; // �W�@����hash (�̤j�O512 bits)
		unsigned long lastHashBytesLength = seedBytesLength;
		copy_bytes(seedBytes, lastHashBytes, lastHashBytesLength); // ��seedBytes�ƻs��lastHashBytes

		unsigned long hashLen = 0;
		unsigned char hash[512 / 8]; // �p��X��hash (�̤j�O512 bits)

		for (int j = 0; j < 1000; j++) {
			unsigned long messageBytesLen = lastLastLastHashBytesLength + lastLastHashBytesLength + lastHashBytesLength;
			unsigned char* messageBytes = malloc(messageBytesLen);
			copy_bytes(lastLastLastHashBytes, messageBytes, lastLastLastHashBytesLength);
			copy_bytes(lastLastHashBytes, messageBytes + lastLastLastHashBytesLength, lastLastHashBytesLength);
			copy_bytes(lastHashBytes, messageBytes + lastLastLastHashBytesLength + lastLastHashBytesLength, lastHashBytesLength);

			//����hash
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
			default:
				printf("Error: Unknown hash algorithm\n");
				return;
				break;
			}

			//last���e��
			lastLastLastHashBytesLength = lastLastHashBytesLength;
			copy_bytes(lastLastHashBytes, lastLastLastHashBytes, lastLastLastHashBytesLength);

			lastLastHashBytesLength = lastHashBytesLength;
			copy_bytes(lastHashBytes, lastLastHashBytes, lastLastHashBytesLength);

			lastHashBytesLength = hashLen;
			copy_bytes(hash, lastHashBytes, lastHashBytesLength);

			//�M�z
			free(messageBytes);

		}

		//�L�X�̫᪺hash
		char lastHashHex[512 / 8 * 2 + 1];
		bytes_to_hex(lastHashBytes, lastHashBytesLength, lastHashHex);
		printf("SHA Hash %d: %s\n", i, lastHashHex);

		//��̫᪺hash��@�U�@����seed
		free(seedBytes);
		seedBytes = malloc(lastHashBytesLength);
		copy_bytes(lastHashBytes, seedBytes, lastHashBytesLength);
		seedBytesLength = lastHashBytesLength;

	}

	//�M�z
	free(seedBytes);	
}


int sha3MCTHash(const int hashAlgorithm, const char* initialSeedString) {
	//return 3;
	hash_state md;
	int err;
	unsigned char* seedBytes = malloc(strlen(initialSeedString) / 2); //��message(�r��)�নbytes
	int seedBytesLength;
	hex_to_bytes(initialSeedString, seedBytes, &seedBytesLength);

	for (int i = 0; i < 100; i++) {

		char lastHashBytes[512 / 8]; // �W�@����hash (�̤j�O512 bits)
		unsigned long lastHashBytesLength = seedBytesLength;
		copy_bytes(seedBytes, lastHashBytes, lastHashBytesLength); // ��seedBytes�ƻs��lastHashBytes

		unsigned long hashLen = 0;
		unsigned char hash[512 / 8]; // �p��X��hash (�̤j�O512 bits)

		for (int j = 0; j < 1000; j++) {
			unsigned long messageBytesLen = lastHashBytesLength;
			unsigned char* messageBytes = malloc(messageBytesLen);	
			copy_bytes(lastHashBytes, messageBytes, lastHashBytesLength);

			//����hash
			switch (hashAlgorithm)
			{
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
				printf("Error: Unknown hash algorithm\n");
				return;
				break;


			}

			//last���e��
		

			lastHashBytesLength = hashLen;
			copy_bytes(hash, lastHashBytes, lastHashBytesLength);

			//�M�z
			free(messageBytes);

		}

		//�L�X�̫᪺hash
		char lastHashHex[512 / 8 * 2 + 1];
		bytes_to_hex(lastHashBytes, lastHashBytesLength, lastHashHex);
		printf("SHA Hash %d: %s\n", i, lastHashHex);

		//��̫᪺hash��@�U�@����seed
		free(seedBytes);
		seedBytes = malloc(lastHashBytesLength);
		copy_bytes(lastHashBytes, seedBytes, lastHashBytesLength);
		seedBytesLength = lastHashBytesLength;

	}

	//�M�z
	free(seedBytes);
}
