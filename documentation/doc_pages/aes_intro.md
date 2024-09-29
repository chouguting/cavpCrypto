@page aes_intro AES 簡介
@tableofcontents

### AES測試中，需要實作以下5種AES模式
- ECB (Electronic codebook)
- CBC (Cipher-block chaining)
- CFB8  (Cipher feedback)
- CFB128  (Cipher feedback)
- CTR (Counter mode)

### 每種模式下都有三種 keyLength: 
- 128 bits 
- 192 bits
- 256 bits

(因此每種模式和每種keyLength搭配下一共有15組配對) 

### 每一種配對要進行以下兩種測試
- AFT測試 (Algorithm Functional Test)
- MCT測試 (Monte Carlo Test)


### AFT測試
AFT測試是最直觀的測試，就是測試加解密結果正不正確  <br>
AES中，只要測試加密和解密

#### 加密函數
@ref aesEncrypt() "AES加密函數實作 aesEncrypt()"  <br>
#### 解密函數
@ref aesDecrypt() "AES解密函數實作 aesDecrypt()"    <br>

### MCT測試
MCT測試會需要對一組初始值重複做多次加解密，看看過程中是否都正確 <br>
詳細演算法要看[這份文件]( https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf ) <br>
(過程中有output的地方都要檢查)

> [!Tip]
> 要注意的是，每種AES模式的MCT測試流程有點不一樣

在我們的C語言實作中，每種AES版本的MCT測試都會有一個對應的函數，例如ECB模式的MCT加密測試函數是`aesEcbMCTEncrypt()` <br>
以下是每種AES模式的MCT測試函數列表: <br>

#### ECB模式
@ref aesEcbMCTEncrypt() "ECB模式的MCT加密測試函數 aesEcbMCTEncrypt()"  <br>
@ref aesEcbMCTDecrypt() "ECB模式的MCT解密測試函數 aesEcbMCTDecrypt()"  <br>
#### CBC模式
@ref aesCbcMCTEncrypt() "CBC模式的MCT加密測試函數 aesCbcMCTEncrypt()" <br>
@ref aesCbcMCTDecrypt() "CBC模式的MCT解密測試函數 aesCbcMCTDecrypt()"   <br>
#### CFB8模式
@ref aesCfb8MCTEncrypt() "CFB8模式的MCT加密測試函數 aesCfb8MCTEncrypt()" <br>
@ref aesCfb8MCTDecrypt() "CFB8模式的MCT解密測試函數 aesCfb8MCTDecrypt()"  <br>
#### CFB128模式
@ref aesCfb128MCTEncrypt() "CFB128模式的MCT加密測試函數 aesCfb128MCTEncrypt()"  <br>
@ref aesCfb128MCTDecrypt() "CFB128模式的MCT解密測試函數 aesCfb128MCTDecrypt()" <br>
#### CTR模式
@ref aesCtrMCTEncrypt() "CTR模式的MCT加密測試函數 aesCtrMCTEncrypt()" <br>
@ref aesCtrMCTDecrypt() "CTR模式的MCT解密測試函數 aesCtrMCTDecrypt()" <br>






