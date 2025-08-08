#include<stdio.h>
#include<string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>
#include <openssl/rand.h>
#include "crypt_eal_rand.h"
#include "cjson/cJSON.h"
#include "bsl_base64.h"
#include <ctype.h>

#define MAX_BUF_SIZE 4096
#define SM9_SIGNATURE_SIZE 104
void sanitize_base64(char *str);
int main(void) {
    const char *inputStr = "Hello openHiTLS Base64 Demo!";
    uint32_t inputLen = (uint32_t)strlen(inputStr);

    // 1. 一次性编码解码示例
    char encodeBuf[HITLS_BASE64_ENCODE_LENGTH(inputLen)];
    uint32_t encodeLen = sizeof(encodeBuf);

    int32_t ret = BSL_BASE64_Encode((const uint8_t *)inputStr, inputLen, encodeBuf, &encodeLen);
    if (ret != 0) {
        printf("BSL_BASE64_Encode failed: %d\n", ret);
        return -1;
    }
    encodeBuf[encodeLen] = '\0';  // 确保字符串结束
    printf("一次性编码结果:\n%s\n", encodeBuf);

    uint8_t decodeBuf[HITLS_BASE64_DECODE_LENGTH(encodeLen)];
    uint32_t decodeLen = sizeof(decodeBuf);

    ret = BSL_BASE64_Decode(encodeBuf, encodeLen, decodeBuf, &decodeLen);
    if (ret != 0) {
        printf("BSL_BASE64_Decode failed: %d\n", ret);
        return -1;
    }
    decodeBuf[decodeLen] = '\0'; // 确保字符串结束
    printf("一次性解码结果:\n%s\n", decodeBuf);

    // 2. 流式编码示例
    BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
    if (!ctx) {
        printf("BSL_BASE64_CtxNew failed\n");
        return -1;
    }

    ret = BSL_BASE64_EncodeInit(ctx);
    if (ret != 0) {
        printf("BSL_BASE64_EncodeInit failed: %d\n", ret);
        BSL_BASE64_CtxFree(ctx);
        return -1;
    }

    char streamEncodeBuf[HITLS_BASE64_ENCODE_LENGTH(inputLen)];
    uint32_t totalEncodedLen = 0;

    // 模拟分块输入，每块8字节
    for (uint32_t offset = 0; offset < inputLen; offset += 8) {
        uint32_t chunkLen = (inputLen - offset) > 8 ? 8 : (inputLen - offset);
        uint32_t encodedLen = sizeof(streamEncodeBuf) - totalEncodedLen;
        ret = BSL_BASE64_EncodeUpdate(ctx, (const uint8_t *)(inputStr + offset), chunkLen,
                                      streamEncodeBuf + totalEncodedLen, &encodedLen);
        if (ret != 0) {
            printf("BSL_BASE64_EncodeUpdate failed: %d\n", ret);
            BSL_BASE64_CtxFree(ctx);
            return -1;
        }
        totalEncodedLen += encodedLen;
    }

    uint32_t finalEncodedLen = sizeof(streamEncodeBuf) - totalEncodedLen;
    ret = BSL_BASE64_EncodeFinal(ctx, streamEncodeBuf + totalEncodedLen, &finalEncodedLen);
    if (ret != 0) {
        printf("BSL_BASE64_EncodeFinal failed: %d\n", ret);
        BSL_BASE64_CtxFree(ctx);
        return -1;
    }
    totalEncodedLen += finalEncodedLen;
    streamEncodeBuf[totalEncodedLen] = '\0';

    printf("流式编码结果:\n%s\n", streamEncodeBuf);

    BSL_BASE64_CtxFree(ctx);

    // 流式解码示例类似，这里简单用一次性解码演示
    uint8_t streamDecodeBuf[HITLS_BASE64_DECODE_LENGTH(totalEncodedLen)];
    uint32_t streamDecodeLen = sizeof(streamDecodeBuf);
    ret = BSL_BASE64_Decode(streamEncodeBuf, totalEncodedLen, streamDecodeBuf, &streamDecodeLen);
    if (ret != 0) {
        printf("BSL_BASE64_Decode failed: %d\n", ret);
        return -1;
    }
    streamDecodeBuf[streamDecodeLen] = '\0';
    printf("流式解码结果:\n%s\n", streamDecodeBuf);


    unsigned char recvbuf[MAX_BUF_SIZE] = "MGYEICwxdz3nzkEtlnpVxcyoht2r3M92DJcISiR5AX0M5ZkZA0IABEHpG7Wfp1cf96VFZBdY4O0vU6bzPrHh/7A4lKAgQbhEdg44muy5mT3UXNBGZa6KuiujbiMWqRppyM5CrRUm13k=";
    sanitize_base64((char*)recvbuf);
    // 打印原始Base64编码的签名
    printf("[RSU] 签名: %s\n", recvbuf);
    
    // 打印原始数据的十六进制表示
    uint32_t recvlen = (uint32_t)strlen((const char*)recvbuf);
    for (size_t i = 0; i < recvlen; i++) {
        printf("%02x", recvbuf[i]);
    }
    printf("\n");

    // Base64解码
    uint8_t signature[SM9_SIGNATURE_SIZE];
    uint32_t siglen = sizeof(signature);
    
    // 确保Base64解码函数正确实现
    ret = BSL_BASE64_Decode(recvbuf, recvlen, signature, &siglen);
    if (ret != 0) {
        printf("BSL_BASE64_Decode failed: %d\n", ret);
        return -1;
    }
    
    // 检查解码后的签名长度是否符合预期
    if (siglen != SM9_SIGNATURE_SIZE) {
        printf("签名长度错误: 期望 %d, 实际 %u\n", SM9_SIGNATURE_SIZE, siglen);
        return -1;
    }
    
    // 打印解码后的签名十六进制表示
    for (size_t i = 0; i < SM9_SIGNATURE_SIZE; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    
    return 0;


    return 0;
}
void sanitize_base64(char *str) {
    char *dst = str;
    while (*str) {
        if (isalnum(*str) || *str == '+' || *str == '/' || *str == '=') {
            *dst++ = *str;
        }
        str++;
    }
    *dst = '\0';
}

