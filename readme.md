## **一、目录结构（暂定）**

```plaintext
SM9_PQC_KeyManagement/
├── README.md               		# 项目介绍与运行说明
├── src/                    		# 核心源代码
│   ├── obu.c
│   ├── rsu.c
│   ├── scloud_kem.h             # SCloud+（PQCP KEM）封装：keygen/encaps/decaps
│   ├── scloud_kem.c
│   ├── sm9_utils.h              # SM9（签名）密钥/签名/验签封装
│   ├── sm9_utils.c
│   ├── net.h                    #网络通信模块
│   |── net.c
│   ├── pqtls.h                  # PQTLS 会话结构与对外 API
│   ├── pqtls.c                  # PQTLS send/recv 包装
│   ├── pqtls_defs.h             # 协议常量/枚举
│   ├── pqtls_codec.{c,h}        # TLV/Handshake 编解码
│   ├── pqtls_crypto.{c,h}       # SM3/HMAC/HKDF（openHiTLS）
│   ├── pqtls_keyschedule.{c,h}  # Key schedule（HKDF-SM3）
│   ├── pqtls_sm9_auth.{c,h}     # SM9_CERT_VERIFY 域分离签名/验签
│   ├── pqtls_handshake.{c,h}    # 自定义 TLS-like 握手状态机
│   ├── pqtls_record.{c,h}       # SM4-GCM Record Layer
│   └── common.h                 #结构类型定义
├── keys/                        # 运行时密钥材料（由 setup_keys 生成）
├── Makefile                      # 一键编译（bin/obu, bin/rsu, bin/setup_keys）
├── study/                       #一些开发过程中的demo


```

---

## **二、模块说明**

1. **SM9 身份认证模块**
   * `src/sm9_utils.c` + `src/sm9_utils.h`
   * 功能：
     * 生成 SM9 主密钥、派生用户私钥
     * 调用 **GmSSL** 完成签名与验签
2. **TCP 通信模块**
   * `src/net.c` + `src/net.h`
   * 功能：
     * 封装 **TCP** 接口
     * 发送/接收加密数据包
3. **PQCP（SCloud+ KEM）模块**
   * `src/scloud_kem.c` + `src/scloud_kem.h`
   * 功能：
     * 使用scloud_kem协商秘钥
4. **PQTLS（自定义 TLS-like 协议）模块**
   * `src/pqtls_handshake.c` / `src/pqtls_record.c` 等
   * 功能：
     * 握手：CLIENT_HELLO / SERVER_HELLO / SM9_CERT_VERIFY / CLIENT_KEM / FINISHED
     * 认证：SM9（经典，不抗量子）
     * 密钥交换/会话保密性：SCloud+ KEM（抗量子）
     * 记录层：SM4-GCM（AEAD）+ seq 重放保护
5. **~~测试与演示~~**
   * ~~`tests/`~~
   * ~~测试 SM9 和 PQC 独立功能~~
   * ~~测试端到端认证与加密传输~~
   * ~~可输出性能数据（延迟、带宽、CPU 占用）~~

---

## **三、演示运行方式**

1. **环境配置**

   * 安装git，直接克隆本项目

   ```bash
   sudo apt update
   sudo apt install git -y
   git config --global user.name "username"
   git config --global user.email "useremail"
   git clone https://github.com/Mmandysa/openhitls-sm9-pqcp.git
   ```

   * 进入项目根目录，运行脚本，安装gmssl，openhitls，pqcp，并测试是否安装成功

   ```bash
   cd openhitls-sm9-pqcp
   sudo chmod -x ./set_env.sh
   ./set_env.sh
   ```
2. **生成密钥（目前我已经生成好了，此步略去）**

   ```bash
   make setup_keys
   ./bin/setup_keys
   ```
3. **启动服务端**

   * 项目根目录下编译，运行
   ```bash
   make rsu
   ./bin/rsu
   ```

3. **启动客户端**

   * 项目根目录下编译，运行
   ```bash
   make obu
   ./bin/obu
   ```

4. **观察输出**

   * 身份认证成功日志
   * PQTLS 会话建立成功
   * 加密消息传输成功

5. **一键自测（打印密钥用于比对）**

```bash
make run_test
```

该测试会打印双方 `k_pqc` 与派生出的 `app_key/app_iv`，用于确认认证与密钥协商结果一致。

---

## **四、系统角色理解**

系统为 **车联网/物联网场景** 设计的，典型的 V2X 模型里有两个核心实体：

1. **Client（客户端） = OBU（On-Board Unit，车载单元）**
   * 模拟一辆车的设备
   * 功能：
   * 主动连接 RSU（路边单元）
   * 使用 SM9 身份认证证明“我是谁”
   * 通过 PQC-TLS 建立安全通道
   * 发送和接收加密消息（如车况信息、紧急刹车预警等）
2. **Server（服务端） = RSU（Road Side Unit，路边单元）**
   * 模拟固定的路边设备/基站
   * 功能：
   * 等待车辆连接
   * 验证车辆身份是否合法（SM9 签名验签）
   * 建立 PQC-TLS 加密信道
   * 接收车辆信息并发送控制/广播信息

所以， **server 就是路边基站，client 就是车辆** 。

## 阶段 1：SM9 密钥生成 + 身份认证演示（最基础 & 最关键）

**目标：**

* 初始化 TMC 的 SM9 主密钥对（MSK + MPK）
* 为 OBU 生成 SM9 身份私钥
* OBU 使用 SM9 对消息签名
* RSU 验证 OBU 的 SM9 签名

**你将展示：**

* 无需证书的身份认证（“身份即公钥”）
* 签名 + 验签的完整流程
* 可以看到“车辆身份认证成功”的输出结果

📌 **推荐立即动手实现这部分** ，你只需要 GmSSL 即可完成，不依赖 PQC、TLS 或通信协议， **是整个系统的根基** 。

---

## 阶段 2：SM9 会话密钥协商 + 对称加密通信演示

**目标：**

* OBU 和 RSU 基于 SM9 协议协商一个会话密钥（K）
* 使用 SM4 对数据进行加解密
* 完整模拟一次加密通信（如 OBU 向 RSU 发消息）

**你将展示：**

* 安全的车路通信通道
* SM9 生成对称密钥用于加密数据

📌 **这个阶段是通信加密层的核心** ，实现后就可以模拟传感器数据、定位信息等安全传输。

---

## 阶段 3：引入 PQC 模块，完成混合加密演示（openHiTLS-PQCP）

**目标：**

* 将 SM9 协商出来的会话密钥与 PQC 算法（如 Kyber）协商出的密钥混合（e.g., K = H(K_sm9 || K_pqc)）
* 形成抗量子的安全通道
* 用于传输如私钥、敏感控制指令等内容

**你将展示：**

* 混合密钥生成过程
* 抗量子安全加密通信

📌这部分需要调用 PQCP 库，建议在 SM9 稳定后引入， **不建议一开始就做** 。

---

## 阶段 4：模拟 OBU–RSU–TMC 通信流程（演示系统联动）

**目标：**

* 模拟完整的密钥下发 / 数据上报 / 策略下发流程
* 每个模块运行在独立进程或线程中，互相通信（Socket/消息队列）
* 采用 SM9 + PQC 混合机制保护通信内容

1."hi"

2.RSU公钥

3.kem密文
