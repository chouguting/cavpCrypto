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


/// @brief 產生ECDSA的key pair
///
/// 產生ECDSA的key pair，可以選擇不同的curve
/// @param keypairCurve ECDSA_CURVE_P256, ECDSA_CURVE_P384, ECDSA_CURVE_P521
void ecdsaKeyPair(int keypairCurve);

/// @brief  驗證ECDSA的key pair
///
/// 驗證ECDSA的key pair，可以選擇不同的curve
/// @param keypairCurve 
/// @param qx 
/// @param qy 
/// @return 
int ecdsaKeyVerify(int keypairCurve, char* qx, char* qy);


void ecdsaSignatureGenerate(int keypairCurve, int hashAlgorithm, char* d, char* message);

int ecdsaSignatureVerify(int keypairCurve, int hashAlgorithm, char* qx, char* qy, char* r, char* s, char* message);

#endif