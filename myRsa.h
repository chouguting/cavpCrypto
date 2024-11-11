#pragma once
#include <tomcrypt.h>

char* rsaSignMessage_pkcs1_v1_5(const char* message, const int hashAlgo);
char* rsaSignMessage_pss(const char* message, const int hashAlgo);
int rsaVerifyMessage_pkcs1_v1_5(const char* message, const char* signature, const int hashAlgo, rsa_key* key);
int rsaVerifyMessage_pss(const char* message, const char* signature, const int hashAlgo, rsa_key* key);


/// @brief 產生RSA的key pair
///
/// 產生RSA的key pair，回傳一個rsa_key struct
/// 使用computeAProbablePrimeFactorBasedOnAuxiliaryPrimes()函數計算Probable Prime Factor Based On Auxiliary Primes
/// 然後使用generateKeyPairBasedOnAuxiliaryProbablePrimes()函數產生key pair，以上是兩個rsaKeyPair()用到的內部函式
/// 使用範例:
/// @code{.c}
/// rsa_key key = rsaKeyPair();
/// @endcode
/// @return 一組可用的rsa key pair(type: rsa_key)
rsa_key rsaKeyPair();

/// @brief 產生RSA的簽章(pkcs1_v1_5)
///
/// 產生RSA的簽章(pkcs1_v1_5)，可以選擇不同的hash演算法 <br>
/// 使用範例:
/// @code{.c}
/// char* message = "97F4CBB1A874F3F4F87B14411F97CCC2D02A5B0DB67C5BB"
///                 "01557D74230A05F9578527215FF5E0020A0CA5C6E401E53"
///                 "BD65841AAA9EDE31090ACA0FA99494BF54E9555F7254314"
///                 "7EAD5F9ECE785667B25006CD6EFF549EBD7C5C6474648D5"
///                 "198DB1E2D4BC4454293C730FF389B6F6D05110587FAE217"
///                 "137BE11A3C77D6DBAFAC8";
/// char* signature = rsaSignMessage_pkcs1_v1_5(message, SHA2_256);
/// printf("signature: %s\n", signature);
/// @endcode
/// @param message 要簽章的message
/// @param hashAlgo SHA2_256, SHA2_384, SHA2_512, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256
/// @return pkcs1_v1_5 signature(type: char*)
char* rsaSignMessage_pkcs1_v1_5(const char* message, const int hashAlgo);

/// @brief 產生RSA的簽章(pss)
///
/// 產生RSA的簽章(pss)，可以選擇不同的hash演算法 <br>
/// 使用範例:
/// @code{.c}
/// char* message = "97F4CBB1A874F3F4F87B14411F97CCC2D02A5B0DB67C5BB"
///                 "01557D74230A05F9578527215FF5E0020A0CA5C6E401E53"
///                 "BD65841AAA9EDE31090ACA0FA99494BF54E9555F7254314"
///                 "7EAD5F9ECE785667B25006CD6EFF549EBD7C5C6474648D5"
///                 "198DB1E2D4BC4454293C730FF389B6F6D05110587FAE217"
///                 "137BE11A3C77D6DBAFAC8";
/// char* signature = rsaSignMessage_pss(message, SHA3_384);
/// printf("signature: %s\n", signature);
/// @endcode
/// @param message 要簽章的message
/// @param hashAlgo SHA2_256, SHA2_384, SHA2_512, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256
/// @return pss signature(type: char*)
char* rsaSignMessage_pss(const char* message, const int hashAlgo);

/// @brief 驗證RSA的簽章(pkcs1_v1_5)
///
/// 驗證RSA的簽章(pkcs1_v1_5)，可以選擇不同的hash演算法 <br>
/// 使用範例:
/// @code{.c}
/// char* message = "97F4CBB1A874F3F4F87B14411F97CCC2D02A5B0DB67C5BB"
///                 "01557D74230A05F9578527215FF5E0020A0CA5C6E401E53"
///                 "BD65841AAA9EDE31090ACA0FA99494BF54E9555F7254314"
///                 "7EAD5F9ECE785667B25006CD6EFF549EBD7C5C6474648D5"
///                 "198DB1E2D4BC4454293C730FF389B6F6D05110587FAE217"
///                 "137BE11A3C77D6DBAFAC8";
/// char* signature = "8AA461ED87DE93708814891F394C7B1736D6ADFCD609D8C"
///                   "2B6F89EC0C3A35EB2F8EF1A4619A0E97BCB716E58E21F65"
///                   "559FE2FCD55278DEAAE8DA65543C9F311B9A25883B7BAEE"
///                   "E12FBC812C2815152798DC40FDD5F88D79AFAEA583F6EAB"
///                   "8CCD1FD69DBAE0032EAA78E45BB7956144AB2E13B831E6B"
///                   "2CB5F3E955FD91E5FB034567024F997A8135FD835866DE7"
///                   "7F6849D3E00AE842886329CB5735706F9C99FA2FA37D635"
///                   "E9685395B02B1D0C64DF2B2A11E90ED4937A72783E4764C"
///                   "BBBC56F7F418CC6E17A5CD8B195B596E77BBF81B70E027C"
///                   "D19DEDF2352F1037AC3EF5DF632091D53C6B18FBB8497F6"
///                   "B36589B4EB8F199B96BBB6C3A95B0AD1F4B70390CB";
/// int isValid = rsaVerifyMessage_pkcs1_v1_5(message, signature, SHA2_256, &key); //1
/// printf("isValid: %d\n", isValid);
/// @endcode
/// @param message 要驗證的message
/// @param signature 簽章
/// @param hashAlgo SHA2_256, SHA2_384, SHA2_512, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256
/// @param key rsa_key struct 驗證需用到的公鑰
/// @return 1:成功 0:失敗
int rsaVerifyMessage_pkcs1_v1_5(const char* message, const char* signature, const int hashAlgo, rsa_key* key);

/// @brief 驗證RSA的簽章(pss)
///
/// 驗證RSA的簽章(pss)，可以選擇不同的hash演算法 <br>
/// 使用範例:
/// @code{.c}
/// char* message = "97F4CBB1A874F3F4F87B14411F97CCC2D02A5B0DB67C5BB"
///                 "01557D74230A05F9578527215FF5E0020A0CA5C6E401E53"
///                 "BD65841AAA9EDE31090ACA0FA99494BF54E9555F7254314"
///                 "7EAD5F9ECE785667B25006CD6EFF549EBD7C5C6474648D5"
///                 "198DB1E2D4BC4454293C730FF389B6F6D05110587FAE217"
///                 "137BE11A3C77D6DBAFAC8";
/// char* signature = "821CE8C4267340B6074F1695808772D379250CD14D84F72"
///                   "0B90C1C1C887BA879A20706AB803A33DD28EDD9BC80623D"
///                   "BA3693132098DA68C21C46A706A063F43AF91363E8D09F2"
///                   "6B34E2CDAF8A8F5DC3254363BF70582C51B4FBDF1392A02"
///                   "D4278AC923215948874EF554F8C4CC2D72C78C98FB2A838"
///                   "3077C029E7628AC72091B494C1D8C2DABC903FF832CFE20"
///                   "B97F3C8DCC64939413F33582041D9805291CCEE3D688651"
///                   "A19711C33F6E2A3147145445A2A7B1A3ECEFFA61CD77803"
///                   "55C63401E0E784B75D6D37B2C937E64485C39908C71382F"
///                   "E684278CE9F1628BA5B294AF6E90C0F8FF3EE6C80CDE6B3"
///                   "D26740A76D46759BFC04BF741261D1596BA550CAFB"
/// int isValid = rsaVerifyMessage_pss(message, signature, SHA3_384, &key); //1
/// printf("isValid: %d\n", isValid);
/// @endcode
/// @param message 要驗證的message
/// @param signature 簽章
/// @param hashAlgo SHA2_256, SHA2_384, SHA2_512, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256
/// @param key rsa_key struct 驗證需用到的公鑰
/// @return 1:成功 0:失敗
int rsaVerifyMessage_pss(const char* message, const char* signature, const int hashAlgo, rsa_key* key);
