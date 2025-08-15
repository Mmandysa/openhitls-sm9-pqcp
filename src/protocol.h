#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "common.h"

// RSU 端握手：生成 SCloud+ 密钥对 -> 发送 pub -> 收 OBU 密文 -> 解封 -> SM9 验证
int protocol_rsu_handshake(int fd, const char *obu_id, SessionKeys *ks);

// OBU 端握手：发 hello -> 收 pub -> 封装 -> 发送密文 -> 用 SM9 签名 transcript -> 等待 OK
int protocol_obu_handshake(int fd, const char *obu_id, SessionKeys *ks);

#endif
