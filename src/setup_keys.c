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
 * @brief 程序入口：生成 SM9 签名主密钥与 Client/Server 的签名私钥
 */
int main(void)
{
    const char *client_id = "琼B12345";
    const char *server_id = "RSU_001";

    printf("===== Generating SM9 SIGNATURE Keys (keys/*.pem) =====\n");

    /* 1) 生成签名主密钥对（MSK/MPK） */
    if (sm9_master_init() != APP_OK) {
        fprintf(stderr, "Failed to init SM9 SIGN master key.\n");
        return -1;
    }

    /* 2) 为 Client 颁发签名私钥 */
    if (sm9_issue_prv_for_id(client_id, SM9_CLIENT_SIGN_KEY_PATH) != APP_OK) {
        fprintf(stderr, "Failed to issue SM9 SIGN key for Client.\n");
        return -1;
    }

    /* 3) 为 Server 颁发签名私钥 */
    if (sm9_issue_prv_for_id(server_id, SM9_SERVER_SIGN_KEY_PATH) != APP_OK) {
        fprintf(stderr, "Failed to issue SM9 SIGN key for Server.\n");
        return -1;
    }

    printf("All SM9 SIGN keys generated successfully.\n");
    return 0;
}
