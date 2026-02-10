#include "net.h"
#include "common.h"
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>

/**
 * @brief 创建监听套接字并开始 listen
 */
int net_listen(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return APP_ERR;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return APP_ERR; }
    if (listen(fd, 5) < 0) { close(fd); return APP_ERR; }
    return fd;
}

/**
 * @brief 接受一个新的 TCP 连接
 */
int net_accept(int listen_fd)
{
    return accept(listen_fd, NULL, NULL);
}

/**
 * @brief 连接到指定服务端
 */
int net_connect(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return APP_ERR;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) { close(fd); return APP_ERR; }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return APP_ERR; }
    return fd;
}

/**
 * @brief 发送 len 字节（内部循环直到发送完或失败）
 */
int net_send_all(int fd, const void *buf, int len)
{
    const uint8_t *p = (const uint8_t*)buf;
    int sent = 0;
    while (sent < len) {
        int n = send(fd, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            return APP_ERR;
        }
        if (n == 0) return APP_ERR;
        sent += n;
    }
    return sent;
}

/**
 * @brief 接收 len 字节（内部循环直到接收完或失败）
 */
int net_recv_all(int fd, void *buf, int len)
{
    uint8_t *p = (uint8_t*)buf;
    int got = 0;
    while (got < len) {
        int n = recv(fd, p + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            return APP_ERR;
        }
        if (n == 0) return APP_ERR;
        got += n;
    }
    return got;
}

/**
 * @brief 发送一帧：PacketHeader(type,len) + payload
 */
int net_send_packet(int fd, uint16_t type, const void *payload, uint32_t len)
{
    PacketHeader h = { .type = htons(type), .len = htonl(len) };
    if (net_send_all(fd, &h, sizeof(h)) != sizeof(h)) return APP_ERR;
    if (len != 0) {
        if (!payload) return APP_ERR;
        if (net_send_all(fd, payload, (int)len) != (int)len) return APP_ERR;
    }
    return APP_OK;
}

/**
 * @brief 接收一帧：先读定长头，再按 len 读满 payload
 */
int net_recv_packet(int fd, uint16_t *type, uint8_t *payload, uint32_t *len, uint32_t cap)
{
    printf("[net_recv_packet] waiting for packet...\n");
    PacketHeader h;
    if (net_recv_all(fd, &h, sizeof(h)) != sizeof(h)) return APP_ERR;
    uint16_t t = ntohs(h.type);
    uint32_t l = ntohl(h.len);
    if (l > cap) return APP_ERR;
    if (l > 0) {
        if (net_recv_all(fd, payload, (int)l) != (int)l) return APP_ERR;
    }
    if (type) *type = t;
    if (len) *len = l;
    return APP_OK;
}

/**
 * @brief 关闭套接字
 */
void net_close(int fd)
{
    if (fd >= 0) close(fd);
}

/**
 * @brief 打印帧头信息（调试用）
 */
void print_packet_info(const PacketHeader *header)
{

    if (!header) return;
    uint16_t type = ntohs(header->type);
    printf("Record Type: 0x%04x\n", type);
    printf("Payload Length: %u\n", ntohl(header->len));
}

//根据当前时间获取ISO 8601格式的时间戳
/**
 * @brief 根据当前时间获取 ISO 8601（UTC）格式时间戳
 */
void get_iso8601_timestamp(char *buffer, size_t buffer_size)
{
    time_t now;
    struct tm *utc_time;
    time(&now);
    utc_time = gmtime(&now);
    // 按照ISO 8601格式进行格式化
    strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", utc_time);
}
