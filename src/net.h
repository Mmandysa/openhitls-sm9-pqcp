#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>
#include "common.h"

//创建监听套接字
int  net_listen(int port);
//接受连接
int  net_accept(int listen_fd);
//连接到服务器
int  net_connect(const char *host, int port);
//发送数据
int  net_send_all(int fd, const void *buf, int len);
//接收数据
int  net_recv_all(int fd, void *buf, int len);
//发送数据包
int  net_send_packet(int fd, uint16_t type, const void *payload, uint32_t len);
//接收数据包
int  net_recv_packet(int fd, uint16_t *type, uint8_t *payload, uint32_t *len, uint32_t cap);
//关闭套接字
void net_close(int fd);
//打印包头信息
void print_packet_info(const PacketHeader *header);
//根据当前时间获取ISO 8601格式的时间戳
void get_iso8601_timestamp(char *buffer, size_t buffer_size);

#endif
