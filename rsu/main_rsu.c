// rsu_gmssl.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <gmssl/sm9.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>
#include <openssl/rand.h>
#include "cjson/cJSON.h"

#define LISTEN_PORT 12345
#define BACKLOG 5
#define BUFFER_SIZE 4096

// gcc /home/tys/openhitls-sm9-pqcp/rsu/main_rsu.c -o /home/tys/openhitls-sm9-pqcp/rsu/main_rsu -L/usr/local/lib -lgmssl -lcjson -lcrypto -lssl
// 加载 SM9 主公钥
int load_sm9_master_pubkey(const char *file, SM9_SIGN_MASTER_KEY *mpk) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("打开SM9公钥文件失败");
        return 0;
    }
    if (sm9_sign_master_public_key_from_pem(mpk, fp) != 1) {
        fprintf(stderr, "读取SM9主公钥失败\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

int main() {
    SM9_SIGN_MASTER_KEY mpk;
    char buffer[BUFFER_SIZE];

    // 1. 加载SM9主公钥
    if (!load_sm9_master_pubkey("sm9_sign_master_public.pem", &mpk)) {
        return -1;
    }
    printf("[RSU] 成功加载 SM9 主公钥\n");

    // 2. 创建监听套接字
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); return -1; }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(LISTEN_PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        close(listenfd);
        return -1;
    }

    if (listen(listenfd, BACKLOG) < 0) {
        perror("listen");
        close(listenfd);
        return -1;
    }
    printf("[RSU] 监听端口 %d, 等待连接...\n", LISTEN_PORT);

    // 3. 等待连接
    int connfd = accept(listenfd, NULL, NULL);
    if (connfd < 0) {
        perror("accept");
        close(listenfd);
        return -1;
    }

    // 4. 接收 OBU 的认证请求(JSON)
    int n = recv(connfd, buffer, BUFFER_SIZE - 1, 0);
    if (n <= 0) goto fail;
    buffer[n] = '\0';
    printf("[RSU] 收到认证请求: %s\n", buffer);

    // 解析 JSON 获取 id
    cJSON *root = cJSON_Parse(buffer);
    if (!root) {
        fprintf(stderr, "[RSU] JSON 解析失败\n");
        goto fail;
    }
    cJSON *id_item = cJSON_GetObjectItem(root, "id");
    if (!id_item || !cJSON_IsString(id_item)) {
        fprintf(stderr, "[RSU] JSON 中缺少 id\n");
        cJSON_Delete(root);
        goto fail;
    }
    const char *id = id_item->valuestring;
    printf("[RSU] OBU ID: %s\n", id);

    // 5. 生成挑战 nonce
    unsigned char nonce[32];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "[RSU] 生成 nonce 失败\n");
        cJSON_Delete(root);
        goto fail;
    }

    // 发送挑战给 OBU
    send(connfd, nonce, sizeof(nonce), 0);
    printf("[RSU] 发送挑战 nonce\n");

    // 6. 接收 OBU 的签名
    unsigned char signature[SM9_SIGNATURE_SIZE];
    n = recv(connfd, signature, sizeof(signature), 0);
    if (n != SM9_SIGNATURE_SIZE) {
        fprintf(stderr, "[RSU] 签名长度错误\n");
        cJSON_Delete(root);
        goto fail;
    }

    // 构造 M = nonce || ID
    unsigned char message[64 + 256]; // nonce(32) + id(最长256)
    size_t msglen = 0;
    memcpy(message, nonce, sizeof(nonce));
    msglen += sizeof(nonce);
    memcpy(message + msglen, id, strlen(id));
    msglen += strlen(id);

    // 7. 验证签名
    SM9_SIGN_CTX ctx;
    sm9_verify_init(&ctx);
    sm9_verify_update(&ctx, message, msglen);

    if (sm9_verify_finish(&ctx, signature, SM9_SIGNATURE_SIZE, &mpk, id, strlen(id)) == 1) {
        printf("[RSU] 签名验证成功！\n");
    } else {
        printf("[RSU] 签名验证失败！\n");
        cJSON_Delete(root);
        goto fail;
    }

    cJSON_Delete(root);
    close(connfd);
    close(listenfd);
    return 0;

fail:
    perror("[RSU] 读取数据失败");
    close(connfd);
    close(listenfd);
    return -1;
}