#include <tomcrypt.h>
#include <tommath.h>


const int ECDSA_CURVE_P256 = 1;
const int ECDSA_CURVE_P384 = 2;
const int ECDSA_CURVE_P521 = 3;

void ecdsaKeyPair(int keypairCurve)
{
	ecc_key mykey;
	prng_state prng;
	int err;
	const ltc_ecc_curve* curve;
	//unsigned char qx[32], qy[32], d[32];
	unsigned char* qx, * qy, * d;


	int keysize = (keypairCurve == ECDSA_CURVE_P256) ? 32 : (keypairCurve == ECDSA_CURVE_P384) ? 48 : (keypairCurve == ECDSA_CURVE_P521) ? 66 : 0;

	qx = (unsigned char*)malloc(keysize);
	qy = (unsigned char*)malloc(keysize);
	d = (unsigned char*)malloc(keysize);


	int i;
	crypt_mp_init("ltm"); //�ϥ�libtommath

	
	/* register yarrow */
	if (register_prng(&yarrow_desc) == -1) {
		printf("Error registering Yarrow\n");
		return-1;
	}
	/* �]�wPRNG */
	if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL))
		!= CRYPT_OK) {
		printf("Error setting up PRNG, %s\n", error_to_string(err));
		return-1;
	}

	// ���P - 256���u
	if (keypairCurve == ECDSA_CURVE_P256)
	{
		if ((err = ecc_find_curve("P-256", &curve)) != CRYPT_OK) {
			printf("Error finding P-256 curve: %s\n", error_to_string(err));
			return -1;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P384) // ���P - 384���u
	{
		if ((err = ecc_find_curve("P-384", &curve)) != CRYPT_OK) {
			printf("Error finding P-384 curve: %s\n", error_to_string(err));
			return -1;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P521) // ���P - 521���u
	{
		if ((err = ecc_find_curve("P-521", &curve)) != CRYPT_OK) {
			printf("Error finding P-521 curve: %s\n", error_to_string(err));
			return -1;
		}
	}
	else
	{
		printf("Error finding curve: %s\n", error_to_string(err));
		return -1;
	}
	

	/* ����ECC key */
	if ((err = ecc_make_key_ex(&prng, find_prng("yarrow"), &mykey, curve)) != CRYPT_OK) {
		printf("Error generating ECC keypair: %s\n", error_to_string(err));
		return -1;
	}



	// ������_��qx�Bqy�M�p�_d
    
    ltc_mp.unsigned_write(mykey.pubkey.x, qx);
    ltc_mp.unsigned_write(mykey.pubkey.y, qy);
    ltc_mp.unsigned_write(mykey.k, d);

    // �L�Xqx�Bqy�Md
	printf("qx:");
    for (i = 0; i < keysize; i++) printf("%02X", qx[i]);
    printf("\n");
	printf("qy:");
    for (i = 0; i < keysize; i++) printf("%02X", qy[i]);
    printf("\n");
	printf("d:");
    for (i = 0; i < keysize; i++) printf("%02X", d[i]);
    printf("\n");

    // ����key
    ecc_free(&mykey);
	free(qx);
	free(qy);
	free(d);

}


int ecdsaKeyVerify(int keypairCurve, char* qx, char* qy) {
	const ltc_ecc_curve* curve;
	mp_int x,  y;
	int err;



	crypt_mp_init("ltm"); //�ϥ�libtommath
	mp_init(&x);
	mp_init(&y);


	// �ھ�keypairCurve��ܹ��������u
	if (keypairCurve == ECDSA_CURVE_P256) {
		if ((err = ecc_find_curve("P-256", &curve)) != CRYPT_OK) {
			printf("Error finding P-256 curve: %s\n", error_to_string(err));
			return false;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P384) {
		if ((err = ecc_find_curve("P-384", &curve)) != CRYPT_OK) {
			printf("Error finding P-384 curve: %s\n", error_to_string(err));
			return false;
		}
	}
	else if (keypairCurve == ECDSA_CURVE_P521) {
		if ((err = ecc_find_curve("P-521", &curve)) != CRYPT_OK) {
			printf("Error finding P-521 curve: %s\n", error_to_string(err));
			return false;
		}
	}
	else {
		printf("Invalid curve\n");
		return false;
	}

	// �Nqx�Mqy�q�r���ഫ���j��
	
	if ((err = mp_read_radix(&x, qx, 16)) != CRYPT_OK || (err = mp_read_radix(&y, qy, 16)) != CRYPT_OK) {
		printf("Error reading qx and qy: %s\n", error_to_string(err));
		mp_clear_multi(&x, &y, NULL);
		return false;
	}

	// ���Ҥ��_: �Q�Τ��� y^2 = x^3 + ax + b (mod p) ���Ҥ��_�O�_�b���u�W
	mp_int a,  b,  p,  lhs,  rhs;

	mp_init(&a);
	mp_init(&b);
	mp_init(&p);
	mp_init(&lhs);
	mp_init(&rhs);

	// Ū�����u�Ѽ�
	mp_read_radix(&a, curve->A, 16);
	mp_read_radix(&b, curve->B, 16);
	mp_read_radix(&p, curve->prime, 16);

	// �p�⥪�� y^2 (mod p)
	mp_sqr(&y, &lhs); // y^2
	mp_mod(&lhs, &p, &lhs); // y^2 (mod p)

	// �p��k�� x^3 + ax + b (mod p)
	mp_sqr(&x, &rhs); // x^2
	mp_mulmod(&rhs, &x, &p, &rhs); // x^3 (mod p)
	mp_mulmod(&a, &x, &p, &x); // ax (mod p)
	mp_addmod(&rhs, &x, &p, &rhs); // x^3 + ax (mod p)
	mp_addmod(&rhs, &b, &p, &rhs); // x^3 + ax + b (mod p)

	// ��������M�k��
	if (mp_cmp(&lhs, &rhs) != LTC_MP_EQ) {
		printf("Invalid public key\n");
		//mp_clear_multi(&x, &y, &a, &b, &p, &lhs, &rhs, NULL);
		mp_clear(&x);
		mp_clear(&y);
		mp_clear(&a);
		mp_clear(&b);
		mp_clear(&p);
		mp_clear(&lhs);
		mp_clear(&rhs);
		return false;
	}

	mp_clear(&x);
	mp_clear(&y);
	mp_clear(&a);
	mp_clear(&b);
	mp_clear(&p);
	mp_clear(&lhs);
	mp_clear(&rhs);

	return true;
	
}


