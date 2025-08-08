## **一、目录结构（暂定）**

```plaintext
SM9_PQC_KeyManagement/
├── CMakeLists.txt          		# CMake 构建文件（或 Makefile）
├── README.md               		# 项目介绍与运行说明
├── docs/                  		# 文档资料
│   ├── design_doc.md       		# 系统设计说明书
│   ├── protocol_flow.png   		# 协议流程图
│   └── performance_test.md 		# 性能测试记录
├── scripts/                		# 辅助脚本
│   ├── generate_keys.sh    		# 自动生成 SM9 主密钥与设备私钥
│   └── run_demo.sh        		# 一键启动客户端/服务端演示
├── include/                		# 头文件目录
│   ├── sm9_auth.h          		# SM9 身份认证接口
│   ├── pqc_tls.h           		# PQC-TLS 封装接口
│   ├── key_manager.h       		# 混合密钥管理逻辑
│   └── logger.h            		# 日志模块
├── src/                    		# 核心源代码
│   ├── sm9_auth.cpp        		# SM9 身份认证实现(GmSSL)
│   ├── pqc_tls.cpp         		# PQC-TLS 通信实现(openHiTLS-PQCP)
│   ├── key_manager.cpp     		# 混合密钥派生、管理逻辑
│   ├── logger.cpp          		# 日志记录模块
│   └── utils.cpp          		# 常用工具函数（序列化/反序列化等）
├── server/                 		# 服务端程序
│   ├── main.cpp            		# 服务端入口
│   └── server_app.cpp      		# 服务端逻辑（认证+TLS握手+消息处理）
├── client/                		# 客户端程序
│   ├── main.cpp            		# 客户端入口
│   └── client_app.cpp      		# 客户端逻辑（发起认证+TLS通信）
├── tests/                 		# 单元测试与功能验证
│   ├── test_sm9.cpp        		# 测试 SM9 签名与验签
│   ├── test_pqc_tls.cpp    		# 测试 PQC-TLS 握手与通信
│   └── test_integration.cpp		# 测试端到端认证与加密通信
└── build/                  		# 编译输出目录（CMake 生成）
```

---

## **二、模块说明**

1. **SM9 身份认证模块**
   * `src/sm9_auth.cpp` + `include/sm9_auth.h`
   * 功能：
     * 生成 SM9 主密钥、派生用户私钥
     * 挑战-响应签名认证逻辑
     * 调用 **GmSSL** 完成签名与验签
2. **PQC-TLS 通信模块**
   * `src/pqc_tls.cpp` + `include/pqc_tls.h`
   * 功能：
     * 封装 **openHiTLS-PQCP** 接口
     * 建立 TLS 1.3 会话（Kyber、Dilithium 等套件）
     * 发送/接收加密数据
3. **混合密钥管理模块**
   * `src/key_manager.cpp` + `include/key_manager.h`
   * 功能：
     * 协调 SM9 认证和 PQC 会话
     * 可选 HKDF-SHA3 派生统一会话密钥
     * 管理会话密钥生命周期
4. **客户端与服务端逻辑**
   * `client/` 与 `server/`
   * 功能：
     * 建立 TCP 连接
     * 执行 SM9 认证流程
     * 切换至 PQC-TLS 加密通信
     * 演示发送加密消息
5. **测试与演示**
   * `tests/`
   * 测试 SM9 和 PQC 独立功能
   * 测试端到端认证与加密传输
   * 可输出性能数据（延迟、带宽、CPU 占用）

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
   cd openhitls
   sudo chmod -x ./set_env.sh
   ./set_env.sh
   ```
2. **生成密钥**
3. **启动服务端**

```bash
./build/server_app
```

3. **启动客户端**

```bash
./build/client_app
```

4. **观察输出**

   * 身份认证成功日志
   * TLS 会话建立成功
   * 加密消息传输成功

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
