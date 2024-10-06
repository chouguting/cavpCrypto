#pragma once

extern const int SHAKE_128;
extern const int SHAKE_256;

/// @brief SHAKE 可變長度雜湊函數
///
/// SHAKE 可變長度雜湊函數  <br>
/// 此函式的輸入為雜湊演算法、訊息、雜湊值長度  <br>
/// 此函式的輸出為雜湊值  <br>
/// 使用範例:
/// @code{.c}
/// char* message = "4169C84E8FF3C9B66961646CF18D5654";
/// char output[(3152/8)*2+1];
/// int outLen = 3152;
/// shakeHash(SHAKE_128, message, outLen, output);
/// printf("output: %s\n", output); //57C08C18DF....CB8A79
/// @endcode
/// @param hashAlgorithm  使用的雜湊演算法: SHAKE_128, SHAKE_256
/// @param message  要雜湊的訊息
/// @param outHashLength  希望輸出的雜湊值長度 (bits)
/// @param outHash  輸出的雜湊值 (利用指標回傳)
void shakeHash(const int hashAlgorithm, const char* message, int outHashLength, char* outHash);