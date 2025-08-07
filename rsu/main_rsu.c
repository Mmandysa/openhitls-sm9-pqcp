// rsu_gmssl.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <gmssl/sm9.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>

#define LISTEN_PORT 12345
#define BACKLOG 5

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
    if (!load_sm9_master_pubkey("sm9_sign_master_public.pem", &mpk)) {
        return -1;
    }

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

    printf("等待车辆端连接...\n");
    int connfd = accept(listenfd, NULL, NULL);
    if (connfd < 0) {
        perror("accept");
        close(listenfd);
        return -1;
    }

    // 读取ID长度 + ID
    uint32_t id_len_net;
    if (read(connfd, &id_len_net, sizeof(id_len_net)) <= 0) goto fail;
    uint32_t id_len = ntohl(id_len_net);
    if (id_len <= 0 || id_len > 1024) goto fail;

    char id[1025] = {0};
    if (read(connfd, id, id_len) <= 0) goto fail;
    id[id_len] = 0;

    // 读取签名长度 + 签名
    uint32_t sig_len_net;
    if (read(connfd, &sig_len_net, sizeof(sig_len_net)) <= 0) goto fail;
    uint32_t sig_len = ntohl(sig_len_net);
    if (sig_len <= 0 || sig_len > 512) goto fail;

    uint8_t signature[512];
    if (read(connfd, signature, sig_len) <= 0) goto fail;

    printf("接收到身份请求,ID: %s\n", id);

    SM9_SIGN_CTX ctx;
    sm9_verify_init(&ctx);

    // 追加消息数据
    sm9_verify_update(&ctx, id, strlen((char *)id));

    // 验证签名
    if(sm9_verify_finish(&ctx, signature, SM9_SIGNATURE_SIZE, &mpk, id, strlen(id)))
    {
        printf("签名验证成功！\n");
    } else {
     goto fail;
    }


    close(connfd);
    close(listenfd);
    return 0;

fail:
    perror("读取数据失败");
    close(connfd);
    close(listenfd);
    return -1;
}
