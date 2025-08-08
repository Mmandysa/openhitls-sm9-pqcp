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

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define BUFFER_SIZE 4096
#define password "obu_password"
#define obu_id "京A12345"

int load_sm9_sign_key(const char *file, SM9_SIGN_KEY *msk) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("打开SM9私钥文件失败");
        return 0;
    }
    // 从 PEM 文件加载密钥
    if (sm9_sign_key_info_decrypt_from_pem(msk, password, fp) != 1) {
        fprintf(stderr, "加载SM9私钥失败\n"); 
    }
    fclose(fp);
    return 1;
}

int main() {
    SM9_SIGN_KEY msk;
     unsigned char recvbuf[BUFFER_SIZE];
    int n;

    // 1. 加载SM9用户签名密钥
    if (!load_sm9_sign_key("sm9_user_sign_key.pem", &msk)) {
        return -1;
    }
    printf("[OBU] 成功加载 SM9 用户签名密钥\n");

    // 2. 建立TCP连接
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); //tcp流式套接字
    if (!sockfd) { perror("socket"); return -1; }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    printf("[OBU] 与服务器 %s:%d 建立 TCP 连接\n", SERVER_IP, SERVER_PORT);


    // 3.发送json认证请求
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

    if (sm9_sign_finish(&ctx, &msk,signature, &siglen) != 1){
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

fail:
    perror("发送失败");
    close(sockfd);
    return -1;
}
