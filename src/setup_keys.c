/**
 * @file setup_keys.c
 * @brief 生成本项目演示所需的 SM9（签名）长期密钥材料。
 *
 * 说明：
 * - 本项目的认证使用 SM9 签名，因此仅需要签名主密钥对（MSK/MPK）与双方的签名私钥。
 * - 生成后的 pem 文件默认放在 `keys/` 目录下（见 src/sm9_utils.h 的路径宏）。
 */

#include "common.h"
#include "sm9_utils.h"

#include <stdio.h>

/**
 * @brief 程序入口：生成方案演示所需的 SM9 签名主密钥与多身份私钥
 */
int main(void)
{
    printf("===== Generating SM9 SIGNATURE Keys (keys/*.pem) =====\n");

    if (sm9_issue_demo_keys() != APP_OK) {
        fprintf(stderr, "Failed to issue demo SM9 SIGN keys.\n");
        return -1;
    }

    printf("Issued demo identities:\n");
    printf("  DID  : %s -> %s\n", PQTLS_DEMO_DEVICE_DID, SM9_DID_SIGN_KEY_PATH);
    printf("  PID-A: %s -> %s\n", PQTLS_DEMO_DEVICE_PID_SLOT_A, SM9_PID_SLOT_A_SIGN_KEY_PATH);
    printf("  PID-B: %s -> %s\n", PQTLS_DEMO_DEVICE_PID_SLOT_B, SM9_PID_SLOT_B_SIGN_KEY_PATH);
    printf("  PID-C: %s -> %s\n", PQTLS_DEMO_DEVICE_PID_SLOT_C, SM9_PID_SLOT_C_SIGN_KEY_PATH);
    printf("  RID  : %s -> %s\n", PQTLS_DEMO_RSU_RID, SM9_RID_SIGN_KEY_PATH);
    printf("  SID  : %s -> %s\n", PQTLS_DEMO_CLOUD_SID, SM9_SID_SIGN_KEY_PATH);
    printf("All SM9 SIGN keys generated successfully.\n");
    return 0;
}
