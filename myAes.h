#pragma once


extern const int AES_MODE_ECB;
extern const int AES_MODE_CBC;
extern const int AES_MODE_CFB8;
extern const int AES_MODE_CFB128;
extern const int AES_MODE_CTR;

extern const int AES_KEY_SIZE_128;
extern const int AES_KEY_SIZE_192;
extern const int AES_KEY_SIZE_256;

/// @brief AES加密
///
/// AES的加密，可以選擇不同的模式、不同的key size <br>
/// 此函式的輸入為: AES模式選擇、KEY長度、密鑰、明文字串、初始向量字串  <br>
/// 此函式的輸出為: 密文字串(修改最後一個參數指標指向的空間)、錯誤碼 <br>
/// 使用範例:
/// @code{.c}
/// char* key = "0000000000000000000000000000000000000000000000000000000000000000";
/// char* plaintext = "FFFFFFFFFFFFFFFFFFFFFFFFC0000000";
/// char* initialVector = "00000000000000000000000000000000";
/// char ciphertext[1024];
/// aesEncrypt(AES_MODE_CBC, AES_KEY_SIZE_256, key, plaintext, initialVector, ciphertext); 
/// printf("ciphertext: %s\n", ciphertext); //E2775E4B59C1BC2E31A2078C11B5A08C
/// @endcode
/// @param mode AES_MODE_ECB, AES_MODE_CBC, AES_MODE_CFB8, AES_MODE_CFB128, AES_MODE_CTR
/// @param keySize AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param keyString key的hex string
/// @param plaintextString 明文的hex string
/// @param initialVectorString 初始向量的hex string
/// @param ciphertextString 輸出的密文的hex string
/// @return 0:成功 -1:失敗
/// @attention ECB模式不需要初始向量，所以initialVectorString應設為空字串 (不要設為NULL)
/// @see aesDecrypt()
int aesEncrypt(int mode, int keySize, char* keyString, char* plaintextString, char* initialVectorString, char* ciphertextString);

/// @brief AES解密
/// 
/// AES的解密，可以選擇不同的模式、不同的key size <br>
/// 此函式的輸入為: AES模式選擇、KEY長度、密鑰、密文字串、初始向量字串  <br>
/// 此函式的輸出為: 明文字串(修改最後一個參數指標指向的空間)、錯誤碼 <br>
/// 使用範例:
/// @code{.c}
///	char* key = "B21DCEA468CF34D2CE0C873B2AD4DBCF8A91956DB6783CD0DFC9F95C1C90FA0C";
///	char* ciphertext = "DD3F2C9A21DFC21E1714BFB57B690657";
///	char* initialVector = "88AA5D4678AB8A3C5DFF508B9E7BB7FF";
///	char plaintext[1024];
///	aesDecrypt(AES_MODE_CFB128, AES_KEY_SIZE_256, key, ciphertext, initialVector, plaintext);
///	printf("plaintext: %s\n", plaintext); //7CF68816643C26994D26C0C5B7EC5EFC
/// @endcode

/// @param mode AES_MODE_ECB, AES_MODE_CBC, AES_MODE_CFB8, AES_MODE_CFB128, AES_MODE_CTR
/// @param keySize AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param keyString key的hex string
/// @param ciphertextString 密文的hex string
/// @param initialVectorString 初始向量的hex string
/// @param plaintextString 輸出的明文的hex string
/// @return 0:成功 -1:失敗
/// @attention ECB模式不需要初始向量，所以initialVectorString應設為空字串 (不要設為NULL)
/// @see aesEncrypt()
int aesDecrypt(int mode, int keySize, char* keyString, char* ciphertextString, char* initialVectorString, char* plaintextString);

/// @brief  AES ECB模式的Monte Carlo Test (加密)
///
/// AES ECB模式的Monte Carlo Test (加密)  <br>
/// AES-ECB之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.1 節所描述的Monte Carlo Test – ECB (MCT-ECB) 演算法完成 <br>
/// 此函式的輸入為key大小、明文、及密鑰 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctPlaintext = "3E999BFA92248C700FDA73AACDF6FE3C";
/// char* mctKey = "93D5DFAE5D069713A68CA6003214AE4F97A39767A5A88C95";
/// aesEcbMCTEncrypt(AES_KEY_SIZE_192, mctPlaintext, mctKey);
/// @endcode
/// @param keySize AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param plaintextString 明文的hex string
/// @param keyString key的hex string
void aesEcbMCTEncrypt(int keySize, char* plaintextString, char* keyString);

/// @brief AES ECB模式的Monte Carlo Test (解密)
///
/// AES ECB模式的Monte Carlo Test (解密)  <br>
/// AES-ECB之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.1 節所描述的Monte Carlo Test – ECB (MCT-ECB) 演算法完成 <br>
/// 此函式的輸入為key大小、密文、及密鑰 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctCiphertext = "CCABCC4339B601C08E8B526AF17EE391";
/// char* mctKey = "466A8707CE1A3B937BC6A11803E57A08";
/// aesEcbMCTDecrypt(AES_KEY_SIZE_128, mctCiphertext, mctKey);
/// @endcode
/// @param keySize  AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param ciphertextString  密文的hex string
/// @param keyString  key的hex string
void aesEcbMCTDecrypt(int keySize, char* ciphertextString, char* keyString);


/// @brief AES CBC模式的Monte Carlo Test (加密)
///
/// AES CBC模式的Monte Carlo Test (加密)  <br>
/// AES-CBC之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.2 節所描述的Monte Carlo Test – CBC (MCT-CBC) 演算法完成 <br>
/// 此函式的輸入為key大小、明文、密鑰及初始向量 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctPlaintext = "00CD7E8241EABFA3553EAD1C46DC0568";
/// char* mctKey = "E84ED46D2346D5A01D0B91310C2A081C";
/// char* mctInitialVector = "E86589D3AA6C004E077523E5109F6199";
/// aesCbcMCTEncrypt(AES_KEY_SIZE_128, mctPlaintext, mctKey, mctInitialVector);
/// @endcode

/// @param keySize  AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param plaintextString 明文的hex string
/// @param keyString key的hex string
/// @param initailVectorString 初始向量的hex string
void aesCbcMCTEncrypt(int keySize, char* plaintextString, char* keyString, char* initailVectorString);

/// @brief AES CBC模式的Monte Carlo Test (解密)
///
/// AES CBC模式的Monte Carlo Test (解密)  <br>
/// AES-CBC之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.2 節所描述的Monte Carlo Test – CBC (MCT-CBC) 演算法完成 <br>
/// 此函式的輸入為key大小、密文、密鑰及初始向量 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctCiphertext = "EA73C1416318FCF60537AAD61D9C1740";
/// char* mctKey = "87354C53CE306B6F5D09D9050085B64BB64F72311C423A0122840974C44D9F8B";
/// char* mctInitialVector = "84D31A689C1B7A92364BD4468874DD1B";
/// aesCbcMCTDecrypt(AES_KEY_SIZE_256, mctCiphertext, mctKey, mctInitialVector);
/// @endcode
/// @param keySize AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param ciphertextString 密文的hex string
/// @param keyString key的hex string
/// @param initailVectorString 初始向量的hex string
void aesCbcMCTDecrypt(int keySize, char* ciphertextString, char* keyString, char* initailVectorString);

/// @brief AES CFB8模式的Monte Carlo Test (加密)
///
/// AES CFB8模式的Monte Carlo Test (加密)  <br>
/// AES-CFB8之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.5 節所描述的Monte Carlo Test – CFB8 (MCT-CFB8) 演算法完成 <br>
/// 此函式的輸入為key大小、明文、密鑰及初始向量 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctPlaintext = "5F";
/// char* mctKey = "86048A0BE20AE4CD1C20CD11085160CB5B7EEA5F3D970314";
/// char* mctInitialVector = "1F110844D003CD50923BC9C7A40A9E2E";
/// aesCfb8MCTEncrypt(AES_KEY_SIZE_192, mctPlaintext, mctKey, mctInitialVector);
/// @endcode
/// @param keySize AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param plaintextString 明文的hex string
/// @param keyString key的hex string
/// @param initailVectorString  初始向量的hex string
void aesCfb8MCTEncrypt(int keySize, char* plaintextString, char* keyString, char* initailVectorString);

/// @brief AES CFB8模式的Monte Carlo Test (解密)
///
/// AES CFB8模式的Monte Carlo Test (解密)  <br>
/// AES-CFB8之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.5 節所描述的Monte Carlo Test – CFB8 (MCT-CFB8) 演算法完成 <br>
/// 此函式的輸入為key大小、密文、密鑰及初始向量 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctCiphertext = "C4";
/// char* mctKey = "D058DE728E496598A48D9D3CE5C3FA39";
/// char* mctInitialVector = "4454A28897DA67BA379A2759BC612A7A";
/// aesCfb8MCTDecrypt(AES_KEY_SIZE_128, mctCiphertext, mctKey, mctInitialVector);
/// @endcode
/// @param keySize  AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param ciphertextString  密文的hex string
/// @param keyString  key的hex string
/// @param initailVectorString  初始向量的hex string
void aesCfb8MCTDecrypt(int keySize, char* ciphertextString, char* keyString, char* initailVectorString);

/// @brief AES CFB128模式的Monte Carlo Test (加密)
///
/// AES CFB128模式的Monte Carlo Test (加密)  <br>
/// AES-CFB128之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.6 節所描述的Monte Carlo Test – CFB128 (MCT-CFB128) 演算法完成 <br>
/// 此函式的輸入為key大小、明文、密鑰及初始向量 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctPlaintext = "89FB9451E4048AD1D8810942EF49A73D";
/// char* mctKey = "7C236C0C1AE21DA30A38C5F6F7E672533BA8775E7C936B4D";
/// char* mctInitialVector = "C65128AAC6E678D8BB7049399623BC43";
/// aesCfb128MCTEncrypt(AES_KEY_SIZE_192, mctPlaintext, mctKey, mctInitialVector);
/// @endcode
/// @param keySize  AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param plaintextString  明文的hex string
/// @param keyString  key的hex string
/// @param initailVectorString  初始向量的hex string
void aesCfb128MCTEncrypt(int keySize, char* plaintextString, char* keyString, char* initailVectorString);

/// @brief AES CFB128模式的Monte Carlo Test (解密)
///
/// AES CFB128模式的Monte Carlo Test (解密)  <br>
/// AES-CFB128之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.6 節所描述的Monte Carlo Test – CFB128 (MCT-CFB128) 演算法完成 <br>
/// 此函式的輸入為key大小、密文、密鑰及初始向量 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctCiphertext = "AA4D5E000E28E3856E36110D80732E61";
/// char* mctKey = "4AFC928203A640E26DC0752E78484D4349B946334C4C77297EDEA3A8FE3C6519";
/// char* mctInitialVector = "3F3BEAC49657F44FBE44B582B4ECEB61";
/// aesCfb128MCTDecrypt(AES_KEY_SIZE_256, mctCiphertext, mctKey, mctInitialVector);
/// @endcode
/// @param keySize  AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param ciphertextString  密文的hex string
/// @param keyString  key的hex string
/// @param initailVectorString  初始向量的hex string
void aesCfb128MCTDecrypt(int keySize, char* ciphertextString, char* keyString, char* initailVectorString);

/// @brief AES CTR模式的Monte Carlo Test (加密)
///
/// AES CTR模式的Monte Carlo Test (加密)  <br>
/// AES-CTR之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.1 節所描述的Monte Carlo Test – CBC (MCT-CBC) 演算法完成 <br>
/// 用CBC模式的MCT演算法，是因為文件中沒有提到CTR模式的MCT演算法，所以用CBC模式的MCT演算法來代替 <br>
/// 此函式的輸入為key大小、明文、密鑰及初始向量 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctPlaintext = "834ED5B41F7C1FDE7ECA5079A13F0F93";
/// char* mctKey = "79A75419357738F2C2769C91EA50627B656F7982E3B62603";
/// char* mctInitialVector = "191A9F9247E818F081F621A186102400";
/// aesCtrMCTEncrypt(AES_KEY_SIZE_192, mctPlaintext, mctKey, mctInitialVector);
/// @endcode
/// @param keySize  AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param plaintextString  明文的hex string
/// @param keyString  key的hex string
/// @param initailVectorString  初始向量的hex string
void aesCtrMCTEncrypt(int keySize, char* plaintextString, char* keyString, char* initailVectorString);

/// @brief AES CTR模式的Monte Carlo Test (解密)
///
/// AES CTR模式的Monte Carlo Test (解密)  <br>
/// AES-CTR之蒙地卡羅測試函數，是依照以下[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)中，6.4.1 節所描述的Monte Carlo Test – CBC (MCT-CBC) 演算法完成 <br>
/// 用CBC模式的MCT演算法，是因為文件中沒有提到CTR模式的MCT演算法，所以用CBC模式的MCT演算法來代替 <br>
/// 此函式的輸入為key大小、密文、密鑰及初始向量 <br>
/// 此函式輸出為MCT測試中，100個狀態(state)下的，明密文及密鑰 <br>
/// 使用範例:
/// @code{.c}
/// char* mctCiphertext = "D1536CC9D895E66A2CD2AF2A9E7F51F6";
/// char* mctKey = "B7535C22380E978B78ADE34C092D0E0CCCA8AF5D53FF4A48D44ED14945203149";
/// char* mctInitialVector = "BACF7EAFDF56AA0324C0E8DCE7D95103";
/// aesCtrMCTDecrypt(AES_KEY_SIZE_256, mctCiphertext, mctKey, mctInitialVector);
/// @endcode
/// @param keySize  AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256
/// @param ciphertextString  密文的hex string
/// @param keyString  key的hex string
/// @param initailVectorString  初始向量的hex string
void aesCtrMCTDecrypt(int keySize, char* ciphertextString, char* keyString, char* initailVectorString);