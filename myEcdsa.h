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



void ecdsaKeyPair(int keypairCurve);


int ecdsaKeyVerify(int keypairCurve, char* qx, char* qy);


void ecdsaSignatureGenerate(int keypairCurve, int hashAlgorithm, char* d, char* message);

int ecdsaSignatureVerify(int keypairCurve, int hashAlgorithm, char* qx, char* qy, char* r, char* s, char* message);

#endif