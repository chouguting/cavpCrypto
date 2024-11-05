@page ecdsa_intro ECDSA 簡介
@tableofcontents

### ECDSA有三種版本，分別對應三種橢圓曲線:
- p-256
- p-384
- P-512

### 每一種版本都要支援以下四種功能:
- Key Generation
- Key Verification
- Signature Generation
- Signature Verification

### Key Generation  
Key Generation是產生一對公私鑰的過程，公鑰可以公開，私鑰要保密 <br>
@ref ecdsaKeyPair() "ECDSA的金鑰產生函數 ecdsaKeyPair()" 
<br>
### Key Verification
Key Verification是確認一個公鑰是否合法的過程 <br>
@ref ecdsaKeyVerify() "ECDSA的金鑰驗證函數 ecdsaKeyVerify()" 
<br>
### Signature Generation
Signature Generation是用私鑰對訊息做簽章的過程 <br>
@ref ecdsaSignatureGenerate() "ECDSA的簽章函數 ecdsaSignatureGenerate()"
<br>
### Signature Verification
Signature Verification是用公鑰對簽章做驗證的過程 <br>
@ref ecdsaSignatureVerify() "ECDSA的簽章驗證函數 ecdsaSignatureVerify()"
