# 编译与运行

本项目包含两部分内容：一是基于 openHiTLS + GmSSL 的 `PQTLS` C 侧演示，
二是位于 `demo/index.html` 的交互式前端架构台。你可以先跑 C 侧握手，
再打开前端查看对象、身份、密钥、伪名和轮换流程。

## 依赖位置

仓库默认依赖已经安装到以下位置：

- 头文件：`/usr/local/include/`
- 动态库：`/usr/local/lib/`

`Makefile` 已经带上 `rpath=/usr/local/lib`。如果运行时仍然提示找不到动态
库，你需要手动导出 `LD_LIBRARY_PATH` 或执行 `ldconfig`。

## 编译

在项目根目录执行以下命令：

```bash
make clean
make all
```

编译后会生成以下可执行文件：

- `bin/setup_keys`
- `bin/server`
- `bin/client`
- `bin/pqtls_test`

## 生成演示密钥

首次运行前，你需要先生成演示身份对应的 SM9 签名材料：

```bash
./bin/setup_keys
```

该命令会生成以下文件：

- `keys/sm9_sign_master_key.pem`
- `keys/sm9_sign_master_public.pem`
- `keys/sm9_vehicle_did_sign_key.pem`
- `keys/sm9_vehicle_pid_slot_a_sign_key.pem`
- `keys/sm9_vehicle_pid_slot_b_sign_key.pem`
- `keys/sm9_vehicle_pid_slot_c_sign_key.pem`
- `keys/sm9_rsu_rid_sign_key.pem`
- `keys/sm9_cloud_sid_sign_key.pem`

默认演示身份如下：

- `DID`: `dev:oemA:cn-sh:tbox:TBX00001`
- `PID-A`: `pid:oemA:cn-sh:slot-20260315-0930:0099`
- `PID-B`: `pid:oemA:cn-sh:slot-20260315-0945:0100`
- `PID-C`: `pid:oemA:cn-sh:slot-20260315-1000:0101`
- `RID`: `rsu:cn-sh:pudong:0012`
- `SID`: `svc:aizonec:tsp-auth`

## 运行 C 侧演示

默认配置是车云场景，也就是 `DID -> SID`。

### 默认车云场景

先启动服务端：

```bash
./bin/server
```

再启动客户端：

```bash
./bin/client
```

`bin/server` 和 `bin/client` 现在都支持传入自定义身份和私钥路径，所以你
可以直接切换到其他方案场景。

### 车路场景

以下命令展示 `PID-A -> RID` 的车路接入：

服务端：

```bash
./bin/server \
  rsu:cn-sh:pudong:0012 \
  keys/sm9_rsu_rid_sign_key.pem \
  pid:oemA:cn-sh:slot-20260315-0930:0099
```

客户端：

```bash
./bin/client \
  pid:oemA:cn-sh:slot-20260315-0930:0099 \
  keys/sm9_vehicle_pid_slot_a_sign_key.pem \
  rsu:cn-sh:pudong:0012
```

### 自定义参数格式

你可以按以下格式传参：

- `bin/server [server_id] [server_sign_key_path] [expected_client_id] [port]`
- `bin/client [client_id] [client_sign_key_path] [expected_server_id] [host] [port]`

这让同一套底层握手代码可以直接验证 `DID↔SID` 和 `PID↔RID` 两种接入模
式。

## 一键自测

如果你要快速验证底层实现，可以执行：

```bash
make run_test
```

`bin/pqtls_test` 会在本地回环中同时跑客户端和服务端，并打印握手过程、线
路字段和双方派生出的关键材料，便于核对 `SM9 + Scloud+ + SM3 + SM4-GCM`
这条链路是否闭合。

## 打开交互式前端

前端页面不依赖打包工具，也不需要后端服务。你可以直接在浏览器里打开：

```text
demo/index.html
```

页面支持以下操作：

- 点击主体查看对象、身份、密钥和代码映射
- 点击六层架构查看职责边界
- 单步或自动执行生产注入、车云接入、车路接入、PID 轮换和密钥更新
- 在流程执行时同步高亮主体、链路和会话快照

## 常见问题

### 动态库找不到

如果运行时报 `error while loading shared libraries`，可以执行：

```bash
export LD_LIBRARY_PATH=/usr/local/lib
sudo ldconfig
```

### 修改身份后握手失败

SM9 是标识密码体系，身份串和私钥是一一对应的。你修改了 `client_id`、
`server_id` 或私钥路径之后，必须确保 `bin/setup_keys` 已为该身份签发对
应私钥。

### 前端页面打不开交互

当前前端没有依赖任何远程资源或 `fetch` 请求。只要浏览器支持现代
JavaScript，就可以直接打开 `demo/index.html`。如果你使用非常老的浏览
器，请升级到现代版本。
