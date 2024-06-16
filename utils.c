
#include <stdio.h>
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