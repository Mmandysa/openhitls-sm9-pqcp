# TLS-like（SM9 + PQC）认证与密钥协商：现状分析与实现规划

> 目标：在现有 `gmssl(SM9/SM3/SM4)` + `openHiTLS(PQCP provider / SCloud+)` 的基础上，做出一个“类似 TLS”的 **认证 + 密钥协商 + 安全会话通道** 原型（可跑通、可演示、可扩展）。

---

## 1. 当前项目已经完成了什么（以代码为准）

### 1.1 角色与入口

- **OBU（客户端）**：`src/obu.c`  
  - 连接 `127.0.0.1:5555`，调用 `protocol_obu_handshake()`，握手成功后打印 `k_final_len`。
- **RSU（服务端）**：`src/rsu.c`  
  - `listen/accept` 后调用 `protocol_rsu_handshake()`，握手成功后打印 `k_final_len`。
- **密钥生成**：`src/setup_keys.c`  
  - 生成 SM9 **签名主密钥对**（`sm9_sign_master_key.pem` / `sm9_sign_master_public.pem`）
  - 为 OBU 颁发 **SM9 签名私钥**（`sm9_obu_sign_key.pem`）
  - 生成 SM9 **加密/交换主密钥对**（`sm9_enc_master_key.pem` / `sm9_enc_master_public.pem`）
  - 为 OBU/RSU 颁发 **SM9 交换私钥**（`sm9_obu_enc_key.pem` / `sm9_rsu_enc_key.pem`）

### 1.2 网络与报文封装（“TLS record”的雏形，但目前是明文）

- `src/net.c` / `src/net.h`
  - 基于 TCP 的收发封装
  - 自定义定长包头 `PacketHeader{type,len}`（网络字节序）
  - 当前握手消息通过 `net_send_packet/net_recv_packet` 明文传输

### 1.3 SM9 模块（认证 + SM9 Key Exchange 已实现）

- `src/sm9_utils.c` / `src/sm9_utils.h`
  - SM9 签名：`sign_message()` / `verify_signature()`（用 GmSSL）
  - Hello 消息构造/解析：
    - `generate_message_hello()` 生成：`nonce(32) || RA(65) || sign_id || exch_id || signature`
    - `parse_message_hello()` 校验签名并解析出 `RA` 与两个 ID
    - **注意**：当前 `parse_message_hello()` 采用固定长度假设：
      - `msg_len == 219`
      - `sign_id_len == 9`、`exch_id_len == 9`、`sig_len == 104`
      - 这与当前示例 ID（`"琼B12345"`，UTF-8 字节长度刚好 9）是匹配的，但不具备通用性。
  - SM9 密钥交换（KEX）：
    - OBU：`sm9_kex_obu_start()` 生成 `rA` 并计算 `RA`
    - RSU：`sm9_kex_rsu_respond()` 生成 `rB`，计算 `RB`，并计算 `k_sm9`
    - OBU：`sm9_kex_obu_finish()` 用 `RB` 计算相同的 `k_sm9`
    - `k_sm9` 使用 `SM3-KDF` 派生（输入包含双方 ID、RA/RB、pairing 结果等）

### 1.4 PQC 模块（PQCP/SCloud+ KEM 已实现）

- `src/scloud_kem.c` / `src/scloud_kem.h`
  - `scloud_global_init("/usr/local/lib")`：
    - 创建 `CRYPT_EAL_LibCtx`
    - 设置 provider 加载路径
    - 加载 `pqcp_provider`（`libpqcp_provider.so`）
    - 初始化随机数（`CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, ...)`）
  - RSU 端：
    - `scloud_rsu_keygen()`：生成一次性（本次握手）SCloud+ 公私钥对，并导出
    - `scloud_rsu_decaps()`：解封得到 `k_pqc`
  - OBU 端：
    - `scloud_obu_encaps()`：用 RSU 公钥封装，得到 `ciphertext` 与 `k_pqc`
  - 当前混合密钥：
    - `scloud_mix_keys_sm3()`：`k_final = SM3( k_sm9 || k_pqc || transcript )`

### 1.5 协议模块（“TLS-like 握手骨架”已跑通）

- `src/protocol.c` / `src/protocol.h`
  - **消息流程（当前实现）**
    1. OBU → RSU：`MSG_HELLO`（nonce + RA + 两个 ID + SM9 签名）
    2. RSU：验签、解析 RA、执行 SM9 KEX 生成 `RB` 与 `k_sm9`
    3. RSU → OBU：`MSG_KEM_PUBKEY`（`RB(65) || scloud_pubkey`）
    4. OBU：用 `RB` 完成 SM9 KEX 得到 `k_sm9`；对 scloud_pubkey 做 KEM 封装得到 `k_pqc` 与 `ciphertext`
    5. OBU → RSU：`MSG_KEM_CIPHERTEXT`（ciphertext）
    6. RSU：KEM 解封得到 `k_pqc`
    7. 双方：混合出 `k_final`
  - **transcript**：
    - 目前把握手中的若干 payload 顺序拼接（不含包头），用于参与 `k_final` 派生

> 结论：项目已经实现了“认证（客户端）+ 双因子密钥协商（SM9 KEX + PQC KEM）+ 统一会话密钥派生”的端到端跑通版，但 **尚未形成真正的“安全会话通道”**（即：握手后数据的加密、完整性、重放保护与密钥确认还没补齐）。

---

## 2. 距离“TLS 认证 + 握手 + 安全通道”还缺什么

从 TLS（尤其 TLS 1.3）视角看，当前代码主要缺少以下“安全闭环”部件：

1. **服务器身份认证（RSU → OBU）**
   - 现有：只有 OBU 在 ClientHello 中签名，RSU 验证 OBU。
   - 缺口：OBU 没有等价的“验证 RSU 身份”的步骤（TLS 的 `Certificate/CertificateVerify` 语义）。
2. **Key Confirmation / Finished（握手完整性与密钥确认）**
   - 现有：双方计算出 `k_final` 后即认为握手完成。
   - 缺口：没有 `Finished` 消息去证明“双方确实持有同一个握手密钥”，也无法在握手阶段发现 MITM/篡改导致的密钥不一致。
3. **Record Layer（握手后数据保护）**
   - 现有：只有 TCP 明文收发。
   - 缺口：需要基于 `k_final` 派生出通信密钥，提供：
     - 机密性（加密）
     - 完整性（认证标签/MAC）
     - 重放保护（序号）
     - 分片/封包边界与 AAD 绑定（类似 TLS record）
4. **报文编码鲁棒性（可扩展性）**
   - 现有：Hello 的 ID 长度与总长是“写死”的。
   - 缺口：需要 TLV/长度字段，便于后续扩展（协商、算法升级、可选字段）。
5. **协商与策略**
   - 现有：SCloud+ 安全等级、算法与参数基本固定。
   - 缺口：需要类似 TLS 的“能力通告 + 选择 + 回显确认”。

---

## 3. 推荐的“最小 TLS-like”目标定义（建议先做到这一版）

为了不把工程做成完整 TLS（成本过高），建议先定义一个 **最小可验收集合**：

- **双向认证**：至少 RSU → OBU 必须可验证（可选：再加 OBU → RSU）
- **混合密钥协商**：保留现有 `SM9 KEX + SCloud+ KEM`
- **握手完整性 & 密钥确认**：加入 `Finished`（基于握手 transcript 的 MAC）
- **安全会话通道**：实现一个 record 层（建议 AEAD：SM4-GCM 或 AES-GCM）
- **可扩展编码**：把关键握手消息改成 TLV（至少对 ID/pubkey/ciphertext 这种可变长字段）

---

## 4. 两条实现路线（可二选一，也可先 A 后 B）

### 路线 A：在现有自定义握手上补齐 TLS-like 机制（推荐优先做）

优点：
- 与当前代码一致，改动集中在 `protocol/sm9_utils/net`，最容易“快速闭环”
- 仍然体现“SM9 + PQC”混合握手的创新点

缺点：
- 需要自行实现 record 层与 Finished（容易踩坑，但可控）

### 路线 B：接入 openHiTLS 的 TLS 1.3 做“真 TLS 通道”

思路：
- 保留 SM9 作为“外部认证/授权”（或变成 PSK 派生来源）
- 用 `HITLS_*` API 建 TLS1.3 通道（握手/record/key update/重传等都由库完成）

优点：
- record 层与握手安全性由成熟库实现，工程更稳

难点（需要预研确认）：
- 如何把 SM9 身份语义融入 TLS：PSK 回调 / custom extension / ClientHello callback 等
- TLS1.3 cipher suite 默认是 AES/ChaCha；如果必须国密对称（SM4），可能要走 TLCP 或额外支持

> 建议：**先走路线 A** 完成最小闭环（更贴合当前项目），然后把路线 B 作为“增强版/未来工作”。

---

## 5. 路线 A：详细里程碑规划（建议按顺序推进）

### Milestone 1：把握手消息改成可扩展 TLV（解决“写死长度”问题）

- 目标：Hello / ServerResponse / Ciphertext 等都不再依赖固定长度
- 建议做法：
  - 定义 `HandshakeMessage` 的 TLV 结构（Type/Len/Value），字段至少包括：
    - `sign_id_len + sign_id`
    - `exch_id_len + exch_id`
    - `nonce_len + nonce`
    - `RA_len + RA`（固定 65 也可以，但仍建议带长度）
    - `sig_len + sig`
  - transcript 追加时：追加 **完整握手消息编码**（建议包含字段类型与长度，避免歧义）
- 验收：ID 换成不同长度（含 ASCII/UTF-8）仍能握手成功

### Milestone 2：补齐 RSU → OBU 的身份认证（对应 TLS 的 server auth）

两种等价实现，选其一：

**方案 2.1（更像 TLS CertificateVerify）：ServerAuth 单独消息**
- RSU 在发送 `MSG_KEM_PUBKEY` 后，再发送 `MSG_SERVER_AUTH`：
  - 内容：`rsu_sign_id + sig( SM9_sign( transcript_hash ) )`
- OBU 收到后用 `SIGN_MPK` 验签

**方案 2.2（更简单）：ServerHello 内联签名**
- RSU 把签名直接放进 `MSG_KEM_PUBKEY` payload 中

配套工作：
- 增加 RSU 的 SM9 签名私钥（需要在 `setup_keys.c` 中为 RSU 也颁发签名私钥）
- OBU 端需要知道/配置 `expected_rsu_sign_id`

验收：OBU 能拒绝“未持有 RSU 签名私钥”的伪造服务端

### Milestone 3：加入 Finished（握手完整性与密钥确认）

目标：握手阶段就能发现 MITM/篡改/密钥不一致。

建议流程（简化 TLS 1.3 语义）：

- 双方先计算 `k_final`（或拆分出 `handshake_secret`）
- 派生 `finished_key_c2s` / `finished_key_s2c`
- 计算：
  - `client_finished = HMAC_SM3(finished_key_c2s, transcript_hash)`
  - `server_finished = HMAC_SM3(finished_key_s2c, transcript_hash)`
- 消息：
  - OBU → RSU：`MSG_FINISHED_C`（client_finished）
  - RSU 校验后 → OBU：`MSG_FINISHED_S`（server_finished）

验收：
- 篡改任意握手字节（包括 RB、KEM 公钥/密文、ID）都应导致 Finished 校验失败并断开

### Milestone 4：实现 Record Layer（握手后安全会话通道）

目标：握手后的业务数据走加密通道（对应 TLS record 的功能集合）。

建议最小 record 设计：
- 每个方向维护 `seq`（64-bit），从 0 递增
- 从 `k_final` 派生：
  - `client_write_key` / `server_write_key`
  - `client_write_iv` / `server_write_iv`
- 使用 AEAD：
  - 若坚持国密：SM4-GCM（16-byte key, 12-byte nonce）
  - 或者更易用：AES-128-GCM（OpenSSL/HiTLS 都好找）
- AAD 至少绑定：`type || seq || ciphertext_len`
- nonce 生成建议：`nonce = iv XOR seq`（TLS 1.3 类似思路）

对外 API 形态建议：
- `secure_send(fd, type, plaintext, len, keys, &seq)`
- `secure_recv(fd, &type, plaintext_out, &len, keys, &seq)`

验收：
- OBU 发送业务数据，RSU 解密成功；反向同理
- 重放旧包（同 seq）必须失败

### Milestone 5：演示程序与负向测试

- 正向：
  - 握手成功 → 发送 N 条加密消息 → 双向解密正确
- 负向（至少做 3 个）：
  - OBU 用错误 sign_id / 错误私钥：RSU 应拒绝
  - 篡改 `RB` 或 `KEM pubkey`：Finished 应失败
  - 重放一条加密 record：应失败

---

## 6. 验收标准（建议写进答辩/报告）

1. 握手阶段：
   - OBU 身份可被 RSU 验证（SM9 验签通过/失败路径明确）
   - RSU 身份可被 OBU 验证（SM9 验签通过/失败路径明确）
   - Finished 能检测篡改与密钥不一致
2. 通道阶段：
   - 应用数据加密传输可跑通
   - 具备完整性校验与重放保护
3. 工程性：
   - 报文编码支持可变长 ID / 可扩展字段
   - 关键密钥材料在用完后清理（至少在逻辑上标注清理点）

---

## 7. 路线 B（增强版）：用 openHiTLS 建“真 TLS”通道（预研清单）

如果后续希望“真的像 TLS”，可以考虑把握手/record 交给 openHiTLS：

- 基本调用链（TLS 1.3）：
  1. `HITLS_Config *cfg = HITLS_CFG_NewTLS13Config()`（或 Provider 版本）
  2. 配置 `HITLS_CFG_SetGroups()`（可尝试 `HITLS_HYBRID_X25519_MLKEM768` 等）
  3. 配置 cipher suites（TLS1.3 默认 AES/ChaCha 套件）
  4. 创建 `HITLS_Ctx *ctx = HITLS_New(cfg)`
  5. `BSL_UIO *uio = BSL_UIO_New(BSL_UIO_TcpMethod())` + `BSL_UIO_SetFD(uio, fd)` + `BSL_UIO_SetInit(uio, true)`
  6. `HITLS_SetUio(ctx, uio)`
  7. Client 调 `HITLS_Connect(ctx)` / Server 调 `HITLS_Accept(ctx)` 直到 `HITLS_SUCCESS`
  8. `HITLS_Read/HITLS_Write` 传输应用数据
- SM9 融入点（待选型）：
  - **PSK 模式**：SM9 认证完成后派生 PSK，通过 `HITLS_CFG_SetPsk*Callback` 注入
  - **自定义扩展**：用 `HITLS_CFG_AddCustomExtension` 在 ClientHello/Certificate 等阶段携带 SM9 身份与签名，并在 `HITLS_CFG_SetClientHelloCb` 做验签决策

> 路线 B 的关键是“把 SM9 的身份语义挂到 TLS 的认证点上”，这需要一次专门的预研与最小 PoC。

---

## 8. 下一步我建议你先确认的 3 个决策点

1. 你希望最终是“**自定义 TLS-like 协议**”（路线 A），还是“**真正跑 TLS 1.3**”（路线 B）？
2. record 层对称算法：你希望用 **SM4-GCM**（国密一致性）还是 **AES-GCM**（实现成本更低）？
3. 是否需要 **双向认证**（OBU 与 RSU 都验）？还是只做 server-auth（更贴近常见 TLS 用法）？
# 说明（已更新）

本文件为早期草案，当前以 `pqtls_sm9_scloudplus_protocol_plan.md` 为准（已按该文档实现新的 PQTLS 模块与项目结构）。

