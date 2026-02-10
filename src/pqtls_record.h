#ifndef PQTLS_RECORD_H
#define PQTLS_RECORD_H

#include <stdint.h>

#include "pqtls.h"

/**
 * @file pqtls_record.h
 * @brief PQTLS Record Layer（SM4-GCM）封装。
 *
 * 说明：
 * - 外层 frame：由 net_send_packet/net_recv_packet 完成
 * - 本模块负责 REC_APPDATA 的 payload 结构、SM4-GCM 加解密、seq 与重放保护
 */

/**
 * @brief 发送一条加密的应用数据 record（REC_APPDATA）
 */
int pqtls_record_send_appdata(int fd, PQTLS_Session *sess, uint16_t app_type, const uint8_t *payload,
                              uint32_t payload_len);

/**
 * @brief 接收一条加密的应用数据 record（REC_APPDATA）
 */
int pqtls_record_recv_appdata(int fd, PQTLS_Session *sess, uint16_t *app_type, uint8_t *payload, uint32_t payload_cap,
                              uint32_t *payload_len);

#endif /* PQTLS_RECORD_H */

