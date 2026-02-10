# PQTLS（自定义 TLS-like 协议）规划与报文结构定义

> **定位**：本协议不是标准 TLS，而是“TLS-like”的自定义认证与密钥协商协议。  
> **约束**：非对称/身份相关只使用 **SM9**（认证）与 **SCloud+（PQCP KEM）**（密钥交换/保密性主来源）；对称与杂凑等基础原语调用 **openHiTLS `CRYPT_EAL_*`**（SM3/HMAC/HKDF/SM4-GCM/随机数）。  
> **安全表述建议**：**认证=SM9（经典，不抗量子）**；**密钥交换/会话保密性=PQC（SCloud+ 抗量子）**。

---

## 0. 任务阐述（你要做成什么）

实现一个类似 TLS 1.3 的安全会话建立过程（但包结构完全自定义）：

1. **握手阶段（明文握手 + 强认证/强完整性）**
   - 双向身份认证：OBU 与 RSU 通过 SM9 签名互相证明身份
   - 抗量子密钥协商：使用 SCloud+ KEM（RSU 发公钥，OBU 封装密文，RSU 解封得到共享秘密 `k_pqc`）
   - 握手完整性与密钥确认：使用 `Finished`（HMAC-SM3）确认双方确实得到相同的 `k_pqc` 并且握手 transcript 未被篡改
2. **数据阶段（Record Layer）**
   - 使用 `SM4-GCM` 做 AEAD 加密认证
   - 每方向单调递增序号 `seq` 做重放保护
   - 业务数据在加密通道中传输（类似 TLS record 的 `application_data`）

---

## 1. 角色、信任与预配置（TMC/密钥体系）

### 1.1 角色

- **TMC（可信管理中心）**：生成 SM9 签名主密钥对（MSK/MPK），离线颁发用户签名私钥。
- **RSU（服务端）**：持有自身 SM9 签名私钥 `SK_sig(RSU_ID)`；握手时生成一次性 SCloud+ KEM 密钥对。
- **OBU（客户端）**：持有自身 SM9 签名私钥 `SK_sig(OBU_ID)`；握手时用 RSU 的 SCloud+ 公钥封装。

### 1.2 预配置材料（双方长期持有）

- 公共材料（全网一致）：
  - `SM9_SIGN_MPK`（签名主公钥，所有节点用于验签）
  - 协议常量：版本号、算法集合（本方案固定）
- RSU：
  - `RSU_SIGN_ID`（字符串/字节串）
  - `RSU_SIGN_SK`（SM9 签名私钥，由 TMC 颁发）
- OBU：
  - `OBU_SIGN_ID`
  - `OBU_SIGN_SK`

> 说明：SM9 的“身份即公钥”依赖 `SM9_SIGN_MPK`，因此 OBU/RSU 验签只需 MPK + 对方 ID。

---

## 2. 编码与通用约定（非常重要）

### 2.1 字节序与整型

- 所有多字节整型均为 **网络字节序（big-endian）**。
- `uint24` 表示 3 字节无符号整型（big-endian）。

### 2.2 字符串与 ID

- `*_ID` 统一用 **UTF-8 字节串**表示（不包含 `\0` 终止符）。
- 建议限制 `ID_MAX = 64 bytes`（可与现有 `ID_MAX_LEN` 对齐）。
- **禁止依赖固定字节长度**（避免当前代码里 “琼B12345 恰好 9 bytes” 的脆弱假设）。

### 2.3 长度限制（建议）

- 单条 TCP 帧最大 payload：`MAX_PAYLOAD = 40960`（沿用现有）
- 单条握手 record 负载：`<= 32768`（保留空间给未来扩展）
- 单条应用数据明文：建议 `<= 16384`（对齐 TLS 经验值）

---

## 3. 协议分层与总体帧格式（你“自己定义的包结构”从这里开始）

本协议跑在 TCP 上，采用“**外层定长头 + 内层 record**”：

### 3.1 外层帧头：`PQTLS_FrameHeader`（6 bytes）

沿用你现在的 `PacketHeader` 形态，便于后续落地实现：

| 字段 | 类型 | 长度 | 说明 |
|---|---:|---:|---|
| `type` | `uint16` | 2 | Record 类型（见 3.2） |
| `len` | `uint32` | 4 | payload 字节长度 |

- `type`、`len` 均为 big-endian。
- TCP 层按 `len` 精确收满 payload。

### 3.2 Record 类型：`PQTLS_RecordType`（外层 `type`）

| RecordType | 值 | 加密 | 用途 |
|---|---:|---|---|
| `REC_HANDSHAKE` | `0x0001` | 明文 | 传输握手消息（内部可串多个握手消息） |
| `REC_APPDATA` | `0x0002` | **必须加密** | 传输应用数据/加密后的 alert |
| `REC_ALERT_PLAIN` | `0x0003` | 明文 | 握手失败时的错误提示（可选实现） |

> 建议：握手成功后不再发送明文 `REC_ALERT_PLAIN`，所有告警都走 `REC_APPDATA`（加密保护，避免被注入造成误关闭）。

---

## 4. TLV 编码（握手消息 body 的统一编码方式）

### 4.1 `PQTLS_TLV` 格式

| 字段 | 类型 | 长度 | 说明 |
|---|---:|---:|---|
| `t` | `uint16` | 2 | TLV 类型 |
| `l` | `uint16` | 2 | value 长度（bytes） |
| `v` | `uint8[l]` | `l` | value |

- TLV 必须按协议规定出现；未知 TLV：**必须忽略**（为向前兼容）。
- 同一 TLV 可出现多次：若允许多次出现，协议会明确说明；否则出现多次视为错误。

---

## 5. 握手 Record 与握手消息结构（类似 TLS handshake）

### 5.1 握手 record payload：可承载多个握手消息

`REC_HANDSHAKE` 的 payload 是握手消息的 **串联**：

```
-------------------+-------------------+-----+
| HandshakeMsg #1   | HandshakeMsg #2   | ... |
-------------------+-------------------+-----+
```

接收方按“读满 record payload”为止循环解析。

### 5.2 单条握手消息头：`PQTLS_HandshakeHeader`（4 bytes）

对齐 TLS 的设计：

| 字段 | 类型 | 长度 | 说明 |
|---|---:|---:|---|
| `hs_type` | `uint8` | 1 | 握手消息类型（见 5.3） |
| `hs_len` | `uint24` | 3 | body 长度 |

然后紧跟 `hs_body`（`hs_len` bytes）。

### 5.3 握手消息类型：`PQTLS_HandshakeType`

| hs_type | 值 | 发送方 | 说明 |
|---|---:|---|---|
| `CLIENT_HELLO` | `0x01` | OBU→RSU | 客户端能力通告、随机数、身份 ID |
| `SERVER_HELLO` | `0x02` | RSU→OBU | 服务端选择结果、随机数、SCloud+ 公钥 |
| `SM9_CERT_VERIFY` | `0x0F` | 双向 | SM9 签名消息（认证绑定 transcript） |
| `CLIENT_KEM` | `0x03` | OBU→RSU | SCloud+ 密文 |
| `FINISHED` | `0x14` | 双向 | HMAC-SM3 的握手完成校验 |

> 说明：这里的 `SM9_CERT_VERIFY` 与 TLS 的 `CertificateVerify` 语义相同，只是没有 X.509 证书链。

---

## 6. 各握手消息 body 结构（重点：尽可能详细）

### 6.1 公共 TLV 类型定义（所有握手消息通用）

| TLV | t 值 | v 格式 | 说明 |
|---|---:|---|---|
| `TLV_VERSION` | `0x0001` | `uint16` | 协议版本（建议 `0x0001`） |
| `TLV_RANDOM` | `0x0002` | `uint8[32]` | 32 字节随机数 |
| `TLV_SIGN_ID` | `0x0003` | `uint8[len]` | 发送方签名身份 ID |
| `TLV_SUPPORTED_KEM` | `0x0010` | `uint8[n]` | 支持的 KEM 列表（见 6.5） |
| `TLV_SELECTED_KEM` | `0x0011` | `uint8` | 选择的 KEM（见 6.5） |
| `TLV_KEM_PUBKEY` | `0x0012` | `uint8[len]` | SCloud+ KEM 公钥 |
| `TLV_KEM_CIPHERTEXT` | `0x0013` | `uint8[len]` | SCloud+ KEM 密文 |
| `TLV_SUPPORTED_AEAD` | `0x0020` | `uint8[n]` | 支持的 AEAD 列表（见 6.6） |
| `TLV_SELECTED_AEAD` | `0x0021` | `uint8` | 选择的 AEAD（见 6.6） |
| `TLV_SUPPORTED_HASH` | `0x0030` | `uint8[n]` | 支持的 HASH 列表（见 6.7） |
| `TLV_SELECTED_HASH` | `0x0031` | `uint8` | 选择的 HASH（见 6.7） |
| `TLV_SIGNATURE` | `0x00F0` | `uint8[len]` | SM9 签名字节串 |
| `TLV_SIG_ROLE` | `0x00F1` | `uint8` | 0=client, 1=server |
| `TLV_VERIFY_DATA` | `0x00F2` | `uint8[32]` | Finished 校验值（HMAC-SM3 输出） |
| `TLV_EXT` | `0x7FFF` | `uint8[len]` | 扩展（预留） |

### 6.2 `CLIENT_HELLO`（hs_type=0x01）

**目的**：客户端通告能力，提供 client_random 与客户端身份。

**必须包含的 TLV（顺序建议固定）**：

1. `TLV_VERSION`（2 bytes）
2. `TLV_RANDOM`（32 bytes，client_random）
3. `TLV_SIGN_ID`（OBU_SIGN_ID）
4. `TLV_SUPPORTED_KEM`（至少 1 个）
5. `TLV_SUPPORTED_AEAD`（至少 1 个）
6. `TLV_SUPPORTED_HASH`（至少 1 个）

**可选 TLV**：

- `TLV_EXT`（例如设备信息、时间戳、重连 cookie 等）

### 6.3 `SERVER_HELLO`（hs_type=0x02）

**目的**：服务端选择算法套件并提供 server_random 与本次握手的 SCloud+ KEM 公钥。

**必须包含的 TLV**：

1. `TLV_VERSION`
2. `TLV_RANDOM`（server_random）
3. `TLV_SIGN_ID`（RSU_SIGN_ID）
4. `TLV_SELECTED_KEM`
5. `TLV_SELECTED_AEAD`
6. `TLV_SELECTED_HASH`
7. `TLV_KEM_PUBKEY`（SCloud+ public key）

> 注意：`SERVER_HELLO` 本身不带签名。签名由紧随其后的 `SM9_CERT_VERIFY(role=server)` 提供（类似 TLS）。

### 6.4 `SM9_CERT_VERIFY`（hs_type=0x0F）

**目的**：用 SM9 签名把“对方身份”绑定到握手 transcript，实现认证与抗篡改。

**必须包含的 TLV**：

1. `TLV_SIG_ROLE`：`0=client` / `1=server`
2. `TLV_SIGN_ID`：签名者 ID（与 role 对应的实体）
3. `TLV_SIGNATURE`：SM9 签名

**签名输入（必须严格定义，避免实现分歧）**：

- 采用 transcript 哈希而非直接签 transcript（避免大报文开销）。
- 设：
  - `T(n)` = 截止到第 n 条握手消息（不含本条 `SM9_CERT_VERIFY`）的 **握手消息字节串拼接**
  - 每条握手消息字节串 = `hs_type || hs_len || hs_body`（不包含外层 `PQTLS_FrameHeader`）
  - `thash = SM3( T(n) )`
- **domain separation**（强烈建议）：
  - `sig_input = "PQTLS-SM9-SCLOUDPLUS" || 0x00 || role_byte || thash`
  - 其中 `"PQTLS-SM9-SCLOUDPLUS"` 为 ASCII 固定字符串
- `signature = SM9_Sign( SK_sig(SIGN_ID), sig_input )`

**验证**：
- `SM9_Verify( MPK, SIGN_ID, sig_input, signature ) == OK`

### 6.5 `CLIENT_KEM`（hs_type=0x03）

**目的**：客户端发送 SCloud+ 密文，双方由此得到共享秘密 `k_pqc`。

**必须包含的 TLV**：

1. `TLV_KEM_CIPHERTEXT`

> 注意：如果你希望减少 RTT，可以在同一个 `REC_HANDSHAKE` 中把 `CLIENT_KEM`、`SM9_CERT_VERIFY(role=client)`、`FINISHED(role=client)` 依次拼接发送。

### 6.6 `FINISHED`（hs_type=0x14）

**目的**：确认双方确实拥有同一个握手密钥并且 transcript 未被篡改。

**必须包含的 TLV**：

1. `TLV_SIG_ROLE`（0=client,1=server）
2. `TLV_VERIFY_DATA`（32 bytes）

**verify_data 计算**（TLS 1.3 风格）：

- `T(n)`：截止到本条 Finished 之前的所有握手消息拼接
- `thash = SM3( T(n) )`
- `verify_data = HMAC-SM3( finished_key(role), thash )`

其中 `finished_key(role)` 由第 7 节的 key schedule 派生。

---

## 7. 算法标识与协商字段（为了“像 TLS”）

### 7.1 KEM 标识：`PQTLS_KEM_ID`（TLV_SUPPORTED_KEM/SELECTED_KEM）

| KEM_ID | 值 | 含义 |
|---|---:|---|
| `KEM_SCLOUDPLUS_128` | `0x01` | SCloud+（128-bit 安全等级） |
| `KEM_SCLOUDPLUS_192` | `0x02` | SCloud+（192-bit） |
| `KEM_SCLOUDPLUS_256` | `0x03` | SCloud+（256-bit） |

> 映射到实现：对应你代码里 `PQCP_SCLOUDPLUS_KEY_BITS` 传入的 `SCLOUDPLUS_SECBITS1/2/3`。

### 7.2 AEAD 标识：`PQTLS_AEAD_ID`

| AEAD_ID | 值 | 含义 |
|---|---:|---|
| `AEAD_SM4_GCM_128` | `0x01` | SM4-GCM（tag=16, key=16, iv=12） |

### 7.3 HASH 标识：`PQTLS_HASH_ID`

| HASH_ID | 值 | 含义 |
|---|---:|---|
| `HASH_SM3` | `0x01` | SM3（digest=32） |

> 当前协议固定为 SM3/SM4-GCM；“协商字段”是为了结构上像 TLS、以及未来扩展。

---

## 8. 握手流程（消息序列 + transcript 定义）

### 8.1 推荐的握手消息序列（双向认证 + 1-RTT）

```
OBU                                                        RSU
 |--- REC_HANDSHAKE: CLIENT_HELLO ------------------------->|
 |<-- REC_HANDSHAKE: SERVER_HELLO + SM9_CERT_VERIFY(srv) ---|
 |--- REC_HANDSHAKE: CLIENT_KEM + SM9_CERT_VERIFY(cli)
 |                    + FINISHED(cli) --------------------->|
 |<-- REC_HANDSHAKE: FINISHED(srv) -------------------------|
 |--- REC_APPDATA (encrypted) <===========================> |
```

### 8.2 transcript（必须一致，否则签名/Finished 会失败）

- `T` 为按发送/接收顺序拼接的握手消息字节串：
  - `HandshakeMsgBytes = hs_type(1) || hs_len(3) || hs_body(hs_len)`
- `T` 的追加规则：
  - 解析成功一条握手消息后，将其 **原始字节串**（header+body）追加到 `T`
  - `REC_HANDSHAKE` 中若包含多条握手消息，按解析顺序逐条追加

> 建议实现：保存每条握手消息“编码后的 bytes”用于 transcript，避免“结构体重编码”导致不一致。

---

## 9. Key Schedule（抗量子保密性核心：SCloud+ → HKDF-SM3）

### 9.1 KEM 输出

- RSU：
  - 生成临时 SCloud+ 密钥对 `(pk, sk)`（**每连接/每握手一次性**）
  - 发送 `pk` 给 OBU
  - 接收 `ct`，解封得到 `k_pqc`
- OBU：
  - 接收 `pk`
  - 封装得到 `(ct, k_pqc)`，发送 `ct`

### 9.2 基础派生函数

- Hash：`SM3`
- MAC：`HMAC-SM3`
- KDF：`HKDF-SM3`（HMAC-SM3 作为 HKDF 的 MAC）

### 9.3 salt 选择（建议）

- `salt = SM3( "PQTLS-salt" || client_random || server_random )`
- 用该 `salt` 做 HKDF-Extract，可把握手随机数纳入派生过程（不要求保密，但有助于区分会话）。

### 9.4 关键材料与派生（建议最小集合）

设：
- `PRK = HKDF-Extract(salt, IKM = k_pqc)`

派生方向密钥（长度固定）：

- `finished_key_c2s = HKDF-Expand(PRK, info="finished c2s"||thash, L=32)`
- `finished_key_s2c = HKDF-Expand(PRK, info="finished s2c"||thash, L=32)`
- `app_key_c2s      = HKDF-Expand(PRK, info="key c2s"     ||thash, L=16)`（SM4 key）
- `app_iv_c2s       = HKDF-Expand(PRK, info="iv c2s"      ||thash, L=12)`（GCM iv）
- `app_key_s2c      = HKDF-Expand(PRK, info="key s2c"     ||thash, L=16)`
- `app_iv_s2c       = HKDF-Expand(PRK, info="iv s2c"      ||thash, L=12)`

其中 `thash` 可取“握手完成前的 transcript hash”，例如：
- 用于派生 finished_key：`thash = SM3( T_before_client_finished )`
- 或者固定选取 `SM3(完整握手 transcript)` 作为最终 thash（实现更简单，但需要握手完成后才能派生 finished_key；不推荐）。

> 实现建议：按 TLS 1.3 思路，**先派生 finished_key，再算 Finished**，避免循环依赖。

---

## 10. Record Layer（REC_APPDATA）结构：加密应用数据

### 10.1 `REC_APPDATA` payload（加密后）

| 字段 | 类型 | 长度 | 说明 |
|---|---:|---:|---|
| `seq` | `uint64` | 8 | 发送方向序号（从 0 开始递增） |
| `ciphertext` | `uint8[]` | 可变 | SM4-GCM 加密后的密文 |
| `tag` | `uint8[16]` | 16 | GCM tag |

- `ciphertext_len = frame.len - 8 - 16`
- 接收方必须校验：
  - `seq == expected_seq`（否则丢弃并告警）
  - `tag` 校验通过

### 10.2 明文（加密前）应用消息结构：`PQTLS_AppPlaintext`

为了让“业务层也有结构”，建议在加密前放一个小头：

| 字段 | 类型 | 长度 | 说明 |
|---|---:|---:|---|
| `app_type` | `uint16` | 2 | 业务消息类型 |
| `app_len` | `uint32` | 4 | payload 长度 |
| `app_payload` | `uint8[app_len]` | 可变 | 业务数据 |

**建议的 app_type 枚举**（可按你的车联网场景扩展）：

| app_type | 值 | 含义 |
|---|---:|---|
| `APP_PING` | `0x0001` | 心跳 |
| `APP_TEXT` | `0x0002` | 演示文本 |
| `APP_VEH_STATUS` | `0x0101` | 车辆状态上报 |
| `APP_ALERT` | `0xFF01` | 加密告警（替代明文 alert） |

### 10.3 AEAD 细节（SM4-GCM）

- key：`app_key_{dir}`（16 bytes）
- static iv：`app_iv_{dir}`（12 bytes）
- nonce（每记录唯一，TLS 1.3 风格 XOR）：
  - `nonce = app_iv XOR (0x00000000 || seq_be64)`
- AAD（建议强绑定 record 元数据）：
  - `aad = uint16(REC_APPDATA) || uint64(seq) || uint32(ciphertext_len)`

---

## 11. 明文告警（可选）：`REC_ALERT_PLAIN`

握手阶段出错时用于调试（生产可关闭）。

`REC_ALERT_PLAIN` payload：

| 字段 | 类型 | 长度 | 说明 |
|---|---:|---:|---|
| `level` | `uint8` | 1 | 1=warning, 2=fatal |
| `desc` | `uint16` | 2 | 告警描述码 |
| `err` | `int32` | 4 | 底层错误码（可选） |
| `msg_len` | `uint16` | 2 | 文本长度 |
| `msg` | `uint8[msg_len]` | 可变 | UTF-8 文本 |

建议 desc 枚举（示例）：
- `0x0001` decode_error
- `0x0002` unexpected_message
- `0x0003` bad_signature
- `0x0004` kem_failure
- `0x0005` bad_finished

---

## 12. 实现规划（落到代码层的任务拆分）

> 你说“先规划”，这里给出建议的模块化拆分（后续再逐步改代码实现）。

### 12.1 新增/调整的模块建议

1. `src/pqtls_codec.{c,h}`
   - TLV 编解码（读写 uint16/uint24、拼接握手消息、严格长度检查）
2. `src/pqtls_handshake.{c,h}`
   - 状态机：client/server
   - transcript 管理（保存“原始编码 bytes”）
3. `src/pqtls_keyschedule.{c,h}`
   - HKDF-SM3、finished_key、app_key/app_iv 派生（调用 openHiTLS `CRYPT_EAL_Kdf*` / `CRYPT_EAL_Mac*`）
4. `src/pqtls_record.{c,h}`
   - SM4-GCM record 加解密（调用 openHiTLS `CRYPT_EAL_Cipher*`）
   - seq 管理与重放保护
5. `src/pqtls_sm9_auth.{c,h}`
   - SM9 签名/验签封装（可继续调用 GmSSL，或维持现有 `sm9_utils.*` 但把编码移走）
6. `src/pqtls_scloud.{c,h}`
   - SCloud+ KEM 封装（保留你当前 pqcp provider 初始化/encaps/decaps 逻辑，但把长度与内存管理做健壮）

### 12.2 里程碑（建议顺序）

1. **M1：TLV/握手编码彻底去“固定长度假设”**（先把包结构实现出来）
2. **M2：实现 ServerAuth（SM9_CERT_VERIFY role=server）**（先保证客户端能验证服务端）
3. **M3：接入 CLIENT_KEM + ClientAuth + Finished**（握手闭环）
4. **M4：实现 SM4-GCM record + seq + AAD**（进入安全通道）
5. **M5：负向测试与安全加固**（篡改/重放/错误 ID/错密钥）

---

## 13. 测试与验收清单（建议写进报告）

### 13.1 正向

- 能完成握手，双方输出一致的 “握手完成” 状态
- OBU→RSU、RSU→OBU 的 `REC_APPDATA` 解密成功（多条连续发送）

### 13.2 负向（至少做 5 个）

1. 篡改 `SERVER_HELLO` 任一字节 → server signature 验证失败
2. 篡改 `CLIENT_KEM` 密文 → RSU decaps 失败或 Finished 失败
3. 篡改 client Finished → RSU 验证失败
4. 重放旧的 `REC_APPDATA(seq=0)` → seq 检查失败
5. 使用错误 ID/错误 SM9 私钥签名 → 验签失败

---

## 14. 关键安全注意事项（别踩坑）

- **SCloud+ 必须每连接临时生成密钥对**，并在握手结束后清理私钥/ctx（否则前向安全性会变差）。
- transcript 必须使用“接收的原始编码 bytes”追加，避免重编码差异。
- 签名与 Finished 必须覆盖关键字段（random、ID、KEM 公钥/密文、选择参数），否则可能被降级/替换。
- AEAD 的 nonce 必须每条记录唯一（`iv XOR seq` 是推荐做法）。
- 所有 MAC/tag/signature 比较必须使用常量时间比较（避免时序侧信道）。

