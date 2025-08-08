// obu_gmssl.c
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

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define BUFFER_SIZE 4096

// 加载 OBU 私钥
int load_sm9_sign_key(const char *file, SM9_SIGN_KEY *sk) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("打开SM9私钥文件失败");
        return 0;
    }
    if (sm9_sign_key_from_pem(sk, fp) != 1) {
        fprintf(stderr, "读取SM9私钥失败\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

int main() {
    SM9_SIGN_KEY sk;
    int sockfd;
    char sendbuf[BUFFER_SIZE];
    unsigned char recvbuf[BUFFER_SIZE];
    int n;

    const char *obu_id = "OBU_123456";

    // 1. 加载SM9私钥
    if (!load_sm9_sign_key("obu_sign_private.pem", &sk)) {
        return -1;
    }
    printf("[OBU] 成功加载 SM9 私钥\n");

    // 2. 创建 socket 并连接 RSU
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    printf("[OBU] 连接 RSU %s:%d 成功\n", SERVER_IP, SERVER_PORT);

    // 3. 发送认证请求 JSON {"id": "OBU_123456"}
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "id", obu_id);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_str) {
        fprintf(stderr, "[OBU] JSON 创建失败\n");
        close(sockfd);
        return -1;
    }

    if (send(sockfd, json_str, strlen(json_str), 0) != (ssize_t)strlen(json_str)) {
        perror("[OBU] 发送认证请求失败");
        free(json_str);
        close(sockfd);
        return -1;
    }
    printf("[OBU] 发送认证请求: %s\n", json_str);
    free(json_str);

    // 4. 接收挑战 nonce (32字节)
    n = recv(sockfd, recvbuf, 32, 0);
    if (n != 32) {
        fprintf(stderr, "[OBU] 接收 nonce 失败或长度错误\n");
        close(sockfd);
        return -1;
    }
    printf("[OBU] 收到挑战 nonce\n");

    // 5. 构造消息 M = nonce || ID
    unsigned char message[32 + 256];
    size_t msglen = 0;
    memcpy(message, recvbuf, 32);
    msglen += 32;
    memcpy(message + msglen, obu_id, strlen(obu_id));
    msglen += strlen(obu_id);

    // 6. 签名
    SM9_SIGN_CTX ctx;
    unsigned char signature[SM9_SIGNATURE_SIZE];
    size_t siglen = sizeof(signature);

    sm9_sign_init(&ctx);
    sm9_sign_update(&ctx, message, msglen);

    if (sm9_sign_finish(&ctx, signature, &siglen, &sk, obu_id, strlen(obu_id)) != 1) {
        fprintf(stderr, "[OBU] 签名失败\n");
        close(sockfd);
        return -1;
    }
    printf("[OBU] 签名完成，长度: %zu\n", siglen);

    // 7. 发送签名给 RSU
    if (send(sockfd, signature, siglen, 0) != (ssize_t)siglen) {
        perror("[OBU] 发送签名失败");
        close(sockfd);
        return -1;
    }
    printf("[OBU] 签名发送成功\n");

    close(sockfd);
    return 0;
}
