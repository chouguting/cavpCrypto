#ifndef _MY_ECDSA_H_
#define _MY_ECDSA_H_
extern const int ECDSA_CURVE_P256;
extern const int ECDSA_CURVE_P384;
extern const int ECDSA_CURVE_P521;


void ecdsaKeyPair(int keypairCurve);
int ecdsaKeyVerify(int keypairCurve, char* qx, char* qy);

#endif