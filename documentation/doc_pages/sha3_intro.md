@page sha3_intro SHA 3 簡介
@tableofcontents

### SHA3一共有三種模式，對應三種訊息摘要長度
- SHA3-256
- SHA3-384
- SHA3-512
### 每一種模式要進行以下兩種測試
- AFT測試 (Algorithm Functional Test)
- MCT測試 (Monte Carlo Test)


### AFT測試
AFT測試是最直觀的測試，就是測試雜湊結果正不正確  <br>
SHA3的AFT測試只需要測試雜湊值正不正確  <br>

#### 雜湊函數
@ref shaHash() "SHA2或SHA3的雜湊函數實作 shaHash()"  <br>
@remark SHA2和SHA3的雜湊函數是一樣的

### MCT測試
MCT測試(Monte Carlo Test)會需要對一組初始值重複做多次雜湊，看看過程中是否都正確 <br>
SHA3的MCT測試流程演算法要看[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf) 6.2.3節的部分<br>
(過程中有output的地方都要檢查)
@attention SHA2和SHA3的MCT測試流程是不一樣的

#### SHA3 MCT 測試函數
@ref sha3MCTHash() "SHA3的MCT測試函數 sha3MCTHash()"  <br>

