#ifndef _MY_ECDSA_H_
#define _MY_ECDSA_H_
extern const int ECDSA_CURVE_P256;
extern const int ECDSA_CURVE_P384;
extern const int ECDSA_CURVE_P521;

extern const int ECDSA_HASH_SHA2_256;
extern const int ECDSA_HASH_SHA2_384;
extern const int ECDSA_HASH_SHA2_512;
extern const int ECDSA_HASH_SHA3_256;
extern const int ECDSA_HASH_SHA3_384;
extern const int ECDSA_HASH_SHA3_512;
extern const int ECDSA_HASH_SHAKE128;
extern const int ECDSA_HASH_SHAKE256;

void hex_to_bytes(const char* hex, unsigned char* outBytes, unsigned long* outBytesLen);
void bytes_to_hex(unsigned char* bytes, unsigned long bytesLen, char* hex);

void ecdsaKeyPair(int keypairCurve);


int ecdsaKeyVerify(int keypairCurve, char* qx, char* qy);


void ecdsaSignatureGenerate(int keypairCurve, int hashAlgorithm, char* d, char* message);

void ecdsaSignatureVerify(int keypairCurve, int hashAlgorithm, char* qx, char* qy, char* r, char* s, char* message);

#endif