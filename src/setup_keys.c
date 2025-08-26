// setup_keys.c (最终黄金标准版)

#include "common.h"
#include "sm9_utils.h"
#include <stdio.h>

int main() {
    
    // ===== 阶段一：生成签名 (SIGNATURE) 相关的密钥 =====
    printf("===== Generating SM9 SIGNATURE Keys =====\n");

    // 1. 生成签名主密钥对
    if (sm9_master_init() != APP_OK) {
        fprintf(stderr, "Failed to init SIGN master key.\n");
        return -1;
    }

    // 2. 为 OBU 颁发签名私钥
    //    ID: "琼B12345"
    //    File: "sm9_obu_sign_key.pem"
    if (sm9_issue_prv_for_id("琼B12345", "sm9_obu_sign_key.pem") != APP_OK) {
        fprintf(stderr, "Failed to issue SIGN key for OBU.\n");
        return -1;
    }

    // ===== 阶段二：生成加密/交换 (ENCRYPTION/EXCHANGE) 相关的密钥 =====
    printf("\n===== Generating SM9 ENCRYPTION/EXCHANGE Keys =====\n");

    // 3. 生成加密/交换主密钥对
    if (sm9_enc_master_init() != APP_OK) {
        fprintf(stderr, "Failed to init ENC master key.\n");
        return -1;
    }

    // 4. 为 OBU 颁发交换私钥
    //    ID: "琼B12345"
    //    File: "sm9_obu_enc_key.pem"
    if (sm9_issue_enc_prv_for_id("琼B12345", "sm9_obu_enc_key.pem") != APP_OK) {
        fprintf(stderr, "Failed to issue ENC key for OBU.\n");
        return -1;
    }

    // 5. 为 RSU 颁发交换私钥
    //    ID: "RSU_001"
    //    File: "sm9_rsu_enc_key.pem"
    if (sm9_issue_enc_prv_for_id("RSU_001", "sm9_rsu_enc_key.pem") != APP_OK) {
        fprintf(stderr, "Failed to issue ENC key for RSU.\n");
        return -1;
    }
    
    printf("\nAll keys have been generated successfully.\n");
    return 0;
}