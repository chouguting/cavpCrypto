#pragma once
extern const int SHA2_256;
extern const int SHA2_384;
extern const int SHA2_512;
extern const int SHA3_256;
extern const int SHA3_384;
extern const int SHA3_512;

void shaHash(const int hashAlgorithm, const char* message, char* outHash, int* outHashLength);