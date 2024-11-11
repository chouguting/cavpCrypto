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
/// 使用範例:
/// @code{.c}
/// ecdsaKeyPair(ECDSA_CURVE_P256);
/// @endcode
/// @param keypairCurve ECDSA_CURVE_P256, ECDSA_CURVE_P384, ECDSA_CURVE_P521
void ecdsaKeyPair(int keypairCurve);

/// @brief  驗證ECDSA的key pair
///
/// 驗證ECDSA的key pair，可以選擇不同的curve
/// 使用範例:
/// @code{.c}
/// char* qx = "B5524388413982F4A4DDF018240EA61270EA0524F4B7675654AF9B9E754AB8F07B10D80CE44722679E35B4A25B64B09C";
/// char* qy = "F739CF6189E6B750054EA5182E42399780BBB39D1A4BF70DB853857B8E9BA077B77C15D8A8BD0D645D70CDA4D50BF7D5";
/// int result = ecdsaKeyVerify(ECDSA_CURVE_P384, qx, qy); //1
/// printf("result: %d\n", result);
/// 
/// @endcode
/// @param keypairCurve  ECDSA_CURVE_P256, ECDSA_CURVE_P384, ECDSA_CURVE_P521
/// @param qx 公鑰的x座標
/// @param qy 公鑰的y座標
/// @return 1:成功 0:失敗
int ecdsaKeyVerify(int keypairCurve, char* qx, char* qy);

/// @brief 產生ECDSA的簽章
///
/// 產生ECDSA的簽章，可以選擇不同的curve及hash演算法 <br>
/// 使用範例:
/// @code{.c}
/// char* d = "419C5769809C963614837F0B90119BDB403FC71100E08235EA143B9E78C1FE42";
/// char* message = "97F4CBB1A874F3F4F87B14411F97CCC2D02A5B0DB67C5BB"
///                 "01557D74230A05F9578527215FF5E0020A0CA5C6E401E53"
///                 "BD65841AAA9EDE31090ACA0FA99494BF54E9555F7254314"
///                 "7EAD5F9ECE785667B25006CD6EFF549EBD7C5C6474648D5"
///                 "198DB1E2D4BC4454293C730FF389B6F6D05110587FAE217"
///                 "137BE11A3C77D6DBAFAC8";
/// ecdsaSignatureGenerate(ECDSA_CURVE_P256, ECDSA_HASH_SHA2_256, d, message);
/// @endcode
/// @param keypairCurve ECDSA_CURVE_P256, ECDSA_CURVE_P384, ECDSA_CURVE_P521
/// @param hashAlgorithm ECDSA_HASH_SHA2_256, ECDSA_HASH_SHA2_384, ECDSA_HASH_SHA2_512, ECDSA_HASH_SHA3_256, ECDSA_HASH_SHA3_384, ECDSA_HASH_SHA3_512, ECDSA_HASH_SHAKE128, ECDSA_HASH_SHAKE256
/// @param d 私鑰
/// @param message 訊息 
void ecdsaSignatureGenerate(int keypairCurve, int hashAlgorithm, char* d, char* message);

/// @brief 驗證ECDSA的簽章
///
/// 驗證ECDSA的簽章，可以選擇不同的curve及hash演算法
/// 使用範例:
/// @code{.c}
/// char* qx = "765AFA3EEEE046FD5BDA99F7DE707D313C04F29E15579A50C18E193F527EDA87";
/// char* qy = "00A80C57E3E3A416750D5CB936AE3F1BFC75BB4263620DDA272DD3FB26AD4E6507";
/// char* r = "D6B69ED0200EC563CBD3F12240809D7613EFE712A0D95DEB1EFBBD21CB868B42";
/// char* s = "236ADAAE2DCE176EB3EA0193CC4E45EA7CDDF5315ADEC71DFA6062DDD9D0DBE6";
/// char* message = "97F4CBB1A874F3F4F87B14411F97CCC2D02A5B0DB67C5BB01557D74230A05F9578527215FF5E00"
///                 "20A0CA5C6E401E53BD65841AAA9EDE31090ACA0FA99494BF54E9555F72543147EAD5F9ECE78566"
///                 "7B25006CD6EFF549EBD7C5C6474648D5198DB1E2D4BC4454293C730FF389B6F6D05110587FAE217"
///                 "137BE11A3C77D6DBAFAC8";
/// 
/// ecdsaSignatureVerify(ECDSA_CURVE_P256, ECDSA_HASH_SHA2_256, qx, qy, r, s, message);
/// @endcode
/// @param keypairCurve ECDSA_CURVE_P256, ECDSA_CURVE_P384, ECDSA_CURVE_P521 
/// @param hashAlgorithm ECDSA_HASH_SHA2_256, ECDSA_HASH_SHA2_384, ECDSA_HASH_SHA2_512, ECDSA_HASH_SHA3_256, ECDSA_HASH_SHA3_384, ECDSA_HASH_SHA3_512, ECDSA_HASH_SHAKE128, ECDSA_HASH_SHAKE256
/// @param qx 公鑰的x座標
/// @param qy 公鑰的y座標
/// @param r 簽章的r值
/// @param s 簽章的s值
/// @param message 訊息
/// @return 1:成功 0:失敗
int ecdsaSignatureVerify(int keypairCurve, int hashAlgorithm, char* qx, char* qy, char* r, char* s, char* message);

#endif