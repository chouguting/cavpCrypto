@page rsa_intro RSA 簡介
@tableofcontents

### RSA有2種模式，分別對應兩種Padding模式:
- LTC_PKCS_1_V1_5
- LTC_PKCS_1_PSS

### 每種模式都支援以下6種Hashing方式:
- SHA_256
- SHA_384
- SHA_512
- SHA3_256
- SHA3_384
- SHA3_512

(因此Padding和Hashing方式總共有12種組合)

### 每一種組合都要支援以下3種功能:
- Key Generation
- Signature Generation
- Signature Verification

### Key Generation  
Key Generation是產生一對公私鑰的過程，公鑰可以公開，私鑰要保密 <br>
@ref rsaKeyPair() "RSA的金鑰產生函數 rsaKeyPair()" 
<br>

### Signature Generation(for PKCS_1_V1_5)
Signature Generation是用私鑰對訊息做簽章的過程(PKCS_1_V1_5) <br>
@ref rsaSignMessage_pkcs1_v1_5() "RSA的簽章函數 rsaSignMessage_pkcs1_v1_5()"
<br>

### Signature Generation(for PKCS_1_PSS)
Signature Generation是用私鑰對訊息做簽章的過程(PSS) <br>
@ref rsaSignMessage_pss() "RSA的簽章函數 rsaSignMessage_pss()"
<br>

### Signature Verification(for PKCS_1_V1_5)
Signature Verification是用公鑰對簽章做驗證的過程(PKCS_1_V1_5) <br>
@ref rsaVerifyMessage_pkcs1_v1_5() "RSA的簽章驗證函數 rsaVerifyMessage_pkcs1_v1_5()"
<br>

### Signature Verification(for PKCS_1_PSS)
Signature Verification是用公鑰對簽章做驗證的過程(PSS) <br>
@ref rsaVerifyMessage_pss() "RSA的簽章驗證函數 rsaVerifyMessage_pss()"
