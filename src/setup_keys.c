// setup_keys.c
#include "sm9_utils.h" // 假设您把上面的函数声明放在了sm9_utils.h中
#include <stdio.h>

int main() {
    printf("===== Generating SM9 SIGNATURE Keys =====\n");
    if (sm9_master_init() != APP_OK) {
        fprintf(stderr, "Failed to init SIGN master key.\n");
        return -1;
    }
    if (sm9_issue_prv_for_id("OBU_SIGN_ID_123") != APP_OK) { // 假设OBU的签名ID
        fprintf(stderr, "Failed to issue SIGN key for OBU.\n");
        return -1;
    }
    // 您可以为RSU也颁发一个签名私钥
    // ...

    printf("\n===== Generating SM9 ENCRYPTION/EXCHANGE Keys =====\n");
    if (sm9_enc_master_init() != APP_OK) {
        fprintf(stderr, "Failed to init ENC master key.\n");
        return -1;
    }
    if (sm9_issue_enc_prv_for_id("OBU_EXCH_ID_123") != APP_OK) { // 假设OBU的交换ID
        fprintf(stderr, "Failed to issue ENC key for OBU.\n");
        return -1;
    }
    // 为RSU也颁发一个交换私钥
    if (sm9_issue_enc_prv_for_id("RSU_EXCH_ID_456") != APP_OK) {
        fprintf(stderr, "Failed to issue ENC key for RSU.\n");
        return -1;
    }
    
    printf("\nAll keys have been generated successfully.\n");
    return 0;
}