@page shake_intro SHAKE 簡介
@tableofcontents

### SHAKE有兩種模式，對應兩種訊息摘要長度
- SHAKE-128
- SHAKE-256

### 每一種模式要進行以下三種測試
- AFT測試 (Algorithm Functional Test)
- MCT測試 (Monte Carlo Test)
- VOT測試 (Variable Output Test)


### AFT測試
AFT測試是最直觀的測試，就是測試雜湊結果正不正確  <br>
SHAKE的AFT測試只需要測試雜湊值正不正確  <br>
SHAKE-128的輸出應該要是128 bits，SHAKE-256的輸出應該要是256 bits <br>

#### 雜湊函數
@ref shakeHash() "SHAKE的可變長度雜湊函數實作 shakeHash()"  <br>
@attention 因為是可變長度輸出，因五要記得設定正確的輸出長度

### MCT測試
MCT測試(Monte Carlo Test)會需要對一組初始值重複做多次雜湊，看看過程中是否都正確 <br>
SHA3的MCT測試流程演算法要看[這份文件](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf) 6.3.3節的部分<br>
(過程中有output的地方都要檢查)
@remark 和SHA3同一份文件，但流程不同

#### SHAKE MCT 測試函數
尚未實作  <br>

### VOT測試
VOT測試(Variable Output Test)是測試可變長度輸出的雜湊函數是否正確 <br>
在這個測試中，我們會測試不同長度的輸出，看看是否正確 <br>
用戶應該可以設定不同長度的輸出，然後看看是否正確 <br>

#### SHAKE VOT 測試函數
@ref shakeHash() "SHAKE的可變長度雜湊函數實作 shakeHash()"  <br>

