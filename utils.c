
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void hex_to_bytes(const char* hex, unsigned char* outBytes, unsigned long* outBytesLen) {
	*outBytesLen = strlen(hex) / 2;
	for (unsigned long i = 0; i < *outBytesLen; i++) {
		sscanf_s(hex + 2 * i, "%02hhx", &outBytes[i]);
	}
}

void bytes_to_hex(unsigned char* bytes, unsigned long bytesLen, char* hex) {
	for (unsigned long i = 0; i < bytesLen; i++) {
		sprintf_s(hex + 2 * i, 3, "%02X", bytes[i]);
	}
	hex[2 * bytesLen] = '\0';
}

void copy_bytes(unsigned char* src, unsigned char* dest, unsigned long length) {
	for (unsigned long i = 0; i < length; i++) {
		dest[i] = src[i];
	}
}


void xor_strings(char* dest, char* src1, char* src2, int length) {
	//char* src1Byte = malloc(strlen(src1) / 2);
	char* src1Byte =(char *) malloc((strlen(src1) / 2) * sizeof(char));

	char* src2Byte =(char *) malloc(strlen(src2) / 2);
	char* resultBytes = malloc(length / 2);

	int src1ByteLen;
	int src2ByteLen;
	hex_to_bytes(src1, src1Byte, &src1ByteLen);
	hex_to_bytes(src2, src2Byte, &src2ByteLen);

	for (int i = 0; i < length / 2; i++) {
		resultBytes[i] = src1Byte[i] ^ src2Byte[i];
	}

	bytes_to_hex(resultBytes, length / 2, dest);

	//free memory
	free(src1Byte);
	free(src2Byte);
	free(resultBytes);
}