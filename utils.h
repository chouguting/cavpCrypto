#ifndef _UTILS_H_
#define _UTILS_H_

void hex_to_bytes(const char* hex, unsigned char* outBytes, unsigned long* outBytesLen);
void bytes_to_hex(unsigned char* bytes, unsigned long bytesLen, char* hex);
void copy_bytes(unsigned char* src, unsigned char* dest, unsigned long length);
void xor_strings(char* dest, char* src1, char* src2, int length);
void getIthByteInHex(char* hex, int i, char* dest);

#endif