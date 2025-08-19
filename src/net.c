#include "net.h"
#include "common.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>

int net_listen(int port) {
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

int net_accept(int listen_fd) {
    return accept(listen_fd, NULL, NULL);
}

int net_connect(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return APP_ERR;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) { close(fd); return APP_ERR; }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return APP_ERR; }
    return fd;
}

int net_send_all(int fd, const void *buf, int len) {
    const uint8_t *p = (const uint8_t*)buf;
    int sent = 0;
    while (sent < len) {
        int n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return APP_ERR;
        sent += n;
    }
    return sent;
}

int net_recv_all(int fd, void *buf, int len) {
    uint8_t *p = (uint8_t*)buf;
    int got = 0;
    while (got < len) {
        int n = recv(fd, p + got, len - got, 0);
        if (n <= 0) return APP_ERR;
        got += n;
    }
    return got;
}

int net_send_packet(int fd, uint16_t type, const void *payload, uint32_t len) {
    PacketHeader h = { .type = htons(type), .len = htonl(len) };
    if (net_send_all(fd, &h, sizeof(h)) != sizeof(h)) return APP_ERR;
    if (len && payload) {
        if (net_send_all(fd, payload, (int)len) != (int)len) return APP_ERR;
    }
    return APP_OK;
}

int net_recv_packet(int fd, uint16_t *type, uint8_t *payload, uint32_t *len, uint32_t cap) {
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

void net_close(int fd) {
    if (fd >= 0) close(fd);
}
