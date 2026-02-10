# 编译与运行（PQTLS + SM9 + SCloud+）

本项目依赖库已安装在：

- 头文件：`/usr/local/include/`（gmssl / hitls / pqcp / scloudplus）
- 动态库：`/usr/local/lib/`

## 1) 编译

在项目根目录执行：

```bash
make clean
make all
```

生成的可执行文件在 `bin/`：

- `bin/setup_keys`
- `bin/server`
- `bin/client`

## 2) 生成密钥材料（首次运行需要）

```bash
./bin/setup_keys
```

会在 `keys/` 下生成（或覆盖）：

- `keys/sm9_sign_master_key.pem`
- `keys/sm9_sign_master_public.pem`
- `keys/sm9_client_sign_key.pem`
- `keys/sm9_server_sign_key.pem`

## 3) 运行演示

终端 A（先启动服务端）：

```bash
./bin/server
```

终端 B（再启动客户端）：

```bash
./bin/client
```

预期现象：

- 握手成功（SM9 双向认证 + SCloud+ KEM + Finished 校验）
- 随后在加密通道中收发一条 `APP_TEXT` 消息（SM4-GCM）

## 4) 一键自测（打印密钥用于比对）

该测试会在同一进程内启动本地回环 TCP 连接，分别跑客户端/服务端握手，并打印双方的 `k_pqc` 与派生的 `app_key/app_iv` 便于比对：

```bash
make run_test
```

生成的测试程序为 `bin/pqtls_test`（源码：`src/pqtls_test.c`）。

## 4) 常见问题

1. **找不到动态库**

本项目在链接时已加入 `rpath=/usr/local/lib`。若仍报错，可尝试：

```bash
export LD_LIBRARY_PATH=/usr/local/lib
sudo ldconfig
```

2. **修改 ID**

演示默认使用：

- Client ID：`琼B12345`
- Server ID：`RSU_001`

如果修改了 `src/client.c` / `src/server.c` 中的 ID，需要同时重新生成对应的 SM9 签名私钥（可改 `src/setup_keys.c` 后重新执行 `./bin/setup_keys`）。
