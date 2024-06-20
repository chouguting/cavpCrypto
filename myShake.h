#pragma once

extern const int SHAKE_128;
extern const int SHAKE_256;

void shakeHash(const int hashAlgorithm, const char* message, int outHashLength, char* outHash);