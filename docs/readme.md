## PQTLS：基于 openHiTLS + GmSSL 的“类 TLS”混合加密安全通信（SM9 认证 + SCloud+ 抗量子密钥协商）

本项目实现了一个自定义的 TLS-like 协议 **PQTLS**（运行在 TCP 之上），目标是在不引入完整 TLS 协议栈的前提下，完成“认证 + 密钥协商 + 加密记录层”的最小闭环，并限制算法为：

- **认证（身份鉴别）**：SM9 **签名**（GmSSL）  
  - 说明：SM9 本身不是抗量子算法，因此这里的“认证”是经典安全性。
- **密钥交换/保密性**：SCloud+ KEM（openHiTLS 的 PQCP provider）  
  - 说明：会话密钥来自 KEM 共享秘密 `k_pqc`，用于提供抗量子级别的会话保密性。
- **Key Schedule**：HKDF-SM3（openHiTLS `CRYPT_EAL_*`）  
- **Record Layer**：SM4-GCM（openHiTLS `CRYPT_EAL_Cipher*`）

你可以用它做一个“类似 TLS 1.3 语义”的认证与握手过程：握手阶段完成身份认证与密钥派生，随后进入 record 层进行加密通信。

---

## 1. 整体通信方案与握手流程（PQTLS v1）

### 1.1 角色

- **Client（客户端）**：主动发起连接与握手（示例程序：`bin/client`）
- **Server（服务端）**：监听端口并响应握手（示例程序：`bin/server`）

### 1.2 握手消息序列（双向 SM9 认证 + KEM + Finished）

握手阶段的消息顺序如下（`REC_HANDSHAKE` 可合并承载多条 handshake 消息）：

1) Client → Server：`CLIENT_HELLO`  
2) Server → Client：`SERVER_HELLO` + `SM9_CERT_VERIFY(server)`  
3) Client → Server：`CLIENT_KEM` + `SM9_CERT_VERIFY(client)` + `FINISHED(client)`  
4) Server → Client：`FINISHED(server)`

握手成功后进入应用数据阶段：

- Client ↔ Server：`REC_APPDATA`（SM4-GCM 加密）

### 1.3 transcript、认证与 Finished（与 TLS 1.3 类似的思想）

- **transcript**：把每条 handshake 消息的“原始字节串”（含 header）按顺序拼接，得到 `transcript`，再计算：
  - `thash = SM3(transcript)`
- **SM9_CERT_VERIFY**：对某个时刻的 `thash` 进行 SM9 签名（并绑定 role 域分离），用于证明“持有该 ID 对应的 SM9 签名私钥”
- **Finished**：`verify_data = HMAC-SM3(finished_key, thash_before_finished)`，用于防止握手被篡改

---

## 2. 线上通信“包格式”定义（Record / Handshake / TLV / AppData）

本项目协议包结构完全自定义（不是标准 TLS wire format），抓包打印由 `bin/pqtls_test` 完成。

### 2.1 外层帧：PacketHeader + payload

外层帧头结构（网络字节序）见 `src/common.h`：

```c
// type(2) + len(4)
typedef struct {
    uint16_t type;   // RecordType（见 src/pqtls_defs.h）
    uint32_t len;    // payload 长度
} PacketHeader;
```

RecordType（见 `src/pqtls_defs.h`）：

| RecordType | 值 | 含义 |
|---|---:|---|
| `PQTLS_REC_HANDSHAKE` | `0x0001` | 握手明文记录 |
| `PQTLS_REC_APPDATA` | `0x0002` | 应用数据加密记录 |
| `PQTLS_REC_ALERT_PLAIN` | `0x0003` | 明文告警（预留） |

### 2.2 握手记录：payload 内可包含多条 handshake 消息

握手消息 header（见 `src/pqtls_codec.h`）：

```
hs_type(1) || hs_len(3) || hs_body(hs_len)
```

其中 `hs_body` 采用 TLV 列表编码。

HandshakeType（见 `src/pqtls_defs.h`）：

| HandshakeType | 值 | 方向 | 含义 |
|---|---:|---|---|
| `CLIENT_HELLO` | `0x01` | C→S | 能力通告 + 随机数 + 身份ID |
| `SERVER_HELLO` | `0x02` | S→C | 选择算法 + 随机数 + 身份ID + KEM公钥 |
| `CLIENT_KEM` | `0x03` | C→S | KEM 密文（封装输出） |
| `SM9_CERT_VERIFY` | `0x0F` | 双向 | SM9 签名认证（绑定 transcript） |
| `FINISHED` | `0x14` | 双向 | HMAC 校验握手完整性 |

### 2.3 TLV 格式与字段含义

TLV 基本格式（见 `src/pqtls_codec.c`）：

```
t(2) || l(2) || v(l)
```

常用 TLV（见 `src/pqtls_defs.h`）：

| TLV | 值 | 出现位置 | 含义 |
|---|---:|---|---|
| `VERSION` | `0x0001` | CH/SH | 协议版本（当前 `0x0001`） |
| `RANDOM` | `0x0002` | CH/SH | 32 字节随机数（参与 salt/派生） |
| `SIGN_ID` | `0x0003` | CH/SH/CV | 身份 ID（UTF-8 字节串） |
| `SUPPORTED_KEM` | `0x0010` | CH | 支持的 KEM 列表（uint8 列表） |
| `SELECTED_KEM` | `0x0011` | SH | 选定的 KEM（uint8） |
| `KEM_PUBKEY` | `0x0012` | SH | KEM 公钥（变长） |
| `KEM_CIPHERTEXT` | `0x0013` | CKEM | KEM 密文（变长） |
| `SUPPORTED_AEAD` | `0x0020` | CH | 支持的 AEAD 列表 |
| `SELECTED_AEAD` | `0x0021` | SH | 选定的 AEAD |
| `SUPPORTED_HASH` | `0x0030` | CH | 支持的 Hash 列表 |
| `SELECTED_HASH` | `0x0031` | SH | 选定的 Hash |
| `SIG_ROLE` | `0x00F1` | CV/FIN | 标识该消息属于 Client 还是 Server |
| `SIGNATURE` | `0x00F0` | CV | SM9 签名（DER 编码，变长） |
| `VERIFY_DATA` | `0x00F2` | FIN | Finished 校验值（32 字节） |

### 2.4 应用数据记录：REC_APPDATA（SM4-GCM）

`REC_APPDATA` 的 record payload（见 `src/pqtls_record.c`）：

```
seq(8) || ciphertext || tag(16)
```

其中明文在加密前被封装为：

```
app_type(2) || app_len(4) || app_payload(app_len)
```

关键点：

- **nonce 派生**：`nonce = iv XOR (0x00000000 || seq_be64)`（12 字节）
- **AAD**：`rec_type || seq || ciphertext_len`（用于绑定记录类型/序号/长度）
- **重放保护**：接收端要求 `seq == expected_recv_seq`（单调递增）

---

## 3. 目录结构与模块说明

```text
openhitls-sm9-pqcp/
├── src/
│   ├── client.c               # Client 演示程序（连接 + 握手 + 发送/接收 APP_TEXT）
│   ├── server.c               # Server 演示程序（监听 + 握手 + 发送/接收 APP_TEXT）
│   ├── setup_keys.c           # 生成 SM9 签名主密钥与 Client/Server 签名私钥
│   ├── net.{c,h}              # TCP + 外层 PacketHeader(type,len) 收发
│   ├── common.h               # 公共宏与 PacketHeader 定义
│   ├── pqtls.{c,h}            # PQTLS 对外 API（握手/收发 APPDATA）
│   ├── pqtls_defs.h           # 协议常量：RecordType/HandshakeType/TLV/算法ID
│   ├── pqtls_codec.{c,h}      # TLV 与 Handshake header 编解码
│   ├── pqtls_crypto.{c,h}     # SM3/HMAC/HKDF（openHiTLS）
│   ├── pqtls_keyschedule.{c,h}# Key schedule（HKDF-SM3）
│   ├── pqtls_sm9_auth.{c,h}   # SM9_CERT_VERIFY 域分离签名/验签
│   ├── pqtls_handshake.{c,h}  # 握手状态机（收发握手记录、transcript、认证、Finished）
│   ├── pqtls_record.{c,h}     # Record Layer（SM4-GCM 加解密 + seq）
│   ├── scloud_kem.{c,h}       # SCloud+ KEM 封装（PQCP provider）
│   ├── sm9_utils.{c,h}        # SM9 签名密钥生成/加载/签名/验签（GmSSL）
│   └── pqtls_test.c           # 一键自测：带 proxy 抓包打印 + 密钥比对
├── keys/                      # 运行时密钥材料（默认被 .gitignore 忽略）
├── Makefile                   # 一键编译：bin/server、bin/client、bin/setup_keys、bin/pqtls_test
└── BUILD_AND_RUN.md           # 额外的编译运行说明
```

---

## 4. 环境依赖、编译与运行

### 4.1 依赖位置

本项目默认依赖已安装在：

- 头文件：`/usr/local/include/`（gmssl / hitls / pqcp）
- 动态库：`/usr/local/lib/`

Makefile 已加入 `-Wl,-rpath,/usr/local/lib`，一般不需要额外设置 `LD_LIBRARY_PATH`。

### 4.2 编译

```bash
make clean
make all
```

生成：

- `bin/setup_keys`
- `bin/server`
- `bin/client`
- `bin/pqtls_test`

### 4.3 生成 SM9 密钥材料（首次运行需要）

```bash
./bin/setup_keys
```

会在 `keys/` 下生成（或覆盖）：

- `keys/sm9_sign_master_key.pem`
- `keys/sm9_sign_master_public.pem`
- `keys/sm9_client_sign_key.pem`
- `keys/sm9_server_sign_key.pem`

### 4.4 运行演示

终端 A（先启动服务端）：

```bash
./bin/server
```

终端 B（再启动客户端）：

```bash
./bin/client
```

### 4.5 一键自测（强烈推荐：抓包打印 + 密钥比对）

```bash
make run_test
```

该测试会：

- 在本机启动 `server` 线程 + `client` 线程，并加一个本地 `proxy/sniffer` 抓包打印每帧字段
- 打印双方派生出的 `k_pqc / app_key / app_iv` 并进行比对（验收握手与密钥一致性）

---

## 5. 示例运行结果（节选）与“各包字段”解读

下面示例来自 `make run_test` 的输出（已省略部分长字段，仅保留前缀；真实输出以你的运行结果为准）。

### 5.1 ClientHello（C→S，REC_HANDSHAKE）

含义：客户端通告版本/随机数/身份ID/支持的算法列表。

```text
[WIRE][C->S] PacketHeader.type=0x0001 (PQTLS_REC_HANDSHAKE)
[WIRE][C->S] PacketHeader.len=74
[WIRE][C->S][HS#0] hs_type=0x01 (CLIENT_HELLO), hs_len=70
  TLV VERSION=0x0001 (PQTLS_VERSION_V1)
  TLV RANDOM=client_random(32 bytes)
  TLV SIGN_ID="琼B12345"
  TLV SUPPORTED_KEM=[0x01 SCLOUDPLUS_128]
  TLV SUPPORTED_AEAD=[0x01 SM4-GCM-128]
  TLV SUPPORTED_HASH=[0x01 SM3]
```

### 5.2 ServerHello + Server CertVerify（S→C，REC_HANDSHAKE）

含义：服务端选择算法并下发 KEM 公钥；随后用 SM9 对 transcript hash 签名，证明“我是该 Server ID 的拥有者”。

```text
[WIRE][S->C] PacketHeader.type=0x0001 (PQTLS_REC_HANDSHAKE)
[WIRE][S->C] PacketHeader.len=7420
[WIRE][S->C][HS#0] hs_type=0x02 (SERVER_HELLO), hs_len=7288
  TLV RANDOM=server_random(32 bytes)
  TLV SIGN_ID="RSU_001"
  TLV SELECTED_KEM=0x01 (SCLOUDPLUS_128)
  TLV SELECTED_AEAD=0x01 (SM4-GCM-128)
  TLV SELECTED_HASH=0x01 (SM3)
  TLV KEM_PUBKEY(7216 bytes, prefix printed)
[WIRE][S->C][HS#1] hs_type=0x0f (SM9_CERT_VERIFY), hs_len=124
  TLV SIG_ROLE=SERVER
  TLV SIGN_ID="RSU_001"
  TLV SIGNATURE(变长, prefix printed)
```

### 5.3 ClientKEM + Client CertVerify + Client Finished（C→S，REC_HANDSHAKE）

含义：客户端对 KEM 公钥封装得到 `ciphertext` 与共享秘密 `k_pqc`，并回传密文；随后客户端也做一次 SM9 认证；最后发送 Finished 校验值。

```text
[WIRE][C->S] PacketHeader.type=0x0001 (PQTLS_REC_HANDSHAKE)
[WIRE][C->S] PacketHeader.len=5639
[WIRE][C->S][HS#0] hs_type=0x03 (CLIENT_KEM), hs_len=5460
  TLV KEM_CIPHERTEXT(5456 bytes, prefix printed)
[WIRE][C->S][HS#1] hs_type=0x0f (SM9_CERT_VERIFY), hs_len=126
  TLV SIG_ROLE=CLIENT
  TLV SIGN_ID="琼B12345"
  TLV SIGNATURE(...)
[WIRE][C->S][HS#2] hs_type=0x14 (FINISHED), hs_len=41
  TLV SIG_ROLE=CLIENT
  TLV VERIFY_DATA(32 bytes)
```

### 5.4 Server Finished（S→C，REC_HANDSHAKE）

含义：服务端发送 Finished，客户端验证通过后握手完成。

```text
[WIRE][S->C] PacketHeader.type=0x0001 (PQTLS_REC_HANDSHAKE)
[WIRE][S->C] PacketHeader.len=45
[WIRE][S->C][HS#0] hs_type=0x14 (FINISHED), hs_len=41
  TLV SIG_ROLE=SERVER
  TLV VERIFY_DATA(32 bytes)
```

### 5.5 AppData（REC_APPDATA，SM4-GCM）

含义：进入 record 层后，外层为 `seq || ciphertext || tag`；解密后得到 `app_type/app_len/app_payload`。

```text
[WIRE][C->S] PacketHeader.type=0x0002 (PQTLS_REC_APPDATA)
[WIRE][C->S] PacketHeader.len=62
[WIRE][C->S][APPDATA] seq=0
[WIRE][C->S][APPDATA] ciphertext_len=38
[WIRE] tag(GCM)=16 bytes

[TEST][SERVER] 解密后应用明文:
  app_type=0x0002 (APP_TEXT)
  app_len=32
  text="PQTLS test msg: client -> server"
```

---

## 6. 常见问题

1) **找不到动态库**

如果运行时报 `error while loading shared libraries`，可尝试：

```bash
export LD_LIBRARY_PATH=/usr/local/lib
sudo ldconfig
```

2) **修改 Client/Server ID 后握手失败**

SM9 是“身份即公钥”，如果你修改了 `src/client.c` / `src/server.c` 里的 ID，需要同步修改 `src/setup_keys.c` 并重新生成对应的 SM9 签名私钥：

```bash
make setup_keys
./bin/setup_keys
```

