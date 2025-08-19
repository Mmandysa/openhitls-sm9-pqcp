#!/bin/bash

# ==============================================================================
#  SM9-PQCP 项目依赖安装脚本 (项目内运行版)
# ==============================================================================
#
#  功能:
#  1. 安装项目所需的编译工具和依赖库.
#  2. 自动从 Gitee/GitCode 克隆、编译和安装 GmSSL, openHiTLS, PQCP.
#  3. 配置系统动态链接库路径.
#
#  使用方法:
#  1. 将此脚本放置在您的项目根目录 `openhitls_sm9_pqcp/` 下.
#  2. 赋予执行权限: `chmod +x setup_env.sh`
#  3. 使用 sudo 权限运行: `sudo ./setup_env.sh`
#
#  注意: 脚本假定 `src`, `build`, `third_party` 目录已存在。
#
# ==============================================================================

# 如果任何命令执行失败，则立即退出脚本
set -e

# --- 1. 核心依赖安装 ---
sudo apt update
echo "--- [1/5] 正在安装核心依赖 (gcc, cmake, make, libssl-dev, etc.)... ---"
sudo apt install gcc cmake make libssl-dev python3-pip autoconf automake libtool -y
echo "核心依赖安装完成。"
echo ""

# --- 2. 检查脚本位置 ---
echo "--- [2/5] 检查当前目录结构... ---"
if [ ! -d "third_party" ] || [ ! -d "src" ]; then
    echo "错误: 未找到 'third_party' 或 'src' 目录。"
    echo "请确保此脚本位于 'openhitls_sm9_pqcp' 项目根目录下运行。"
    exit 1
fi
echo "目录结构正确，进入 'third_party' 目录开始安装。"
cd third_party
echo ""


# --- 3. 安装 GmSSL ---
echo "--- [3/5] 正在克隆并安装 GmSSL... ---"
git clone https://gitee.com/rootgd/GmSSL.git
cd GmSSL
mkdir -p build
cd build
cmake ..
make
make test
sudo make install
cd ../.. # 返回到 third_party 目录
echo "GmSSL 安装完成。"
echo ""

# --- 4. 安装 PQCP 组件 ---
echo "--- [4/5] 正在克隆并构建 PQCP 组件... ---"
git clone https://gitcode.com/openHiTLS/pqcp.git
cd pqcp
sudo bash ./build_pqcp.sh
cd platform/openhitls/build && sudo make install
cd ../..
cd ..

# --- 5. 配置动态链接库 ---
echo "--- [5/5] 正在配置系统动态链接库... ---"
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/local.conf > /dev/null
sudo cp platform/openhitls/platform/Secure_C/lib/*.so /usr/local/lib/
sudo mkdir -p /usr/local/include/pqcp && sudo cp include/*.h /usr/local/include/pqcp &&sudo cp src/provider/*.h /usr/local/include/pqcp
sudo mkdir -p /usr/local/include/scloudplus &&sudo cp src/scloudplus/src/*.h /usr/local/include/scloudplus/ &&sudo cp src/scloudplus/include/*.h /usr/local/include/scloudplus/
sudo cp build/libpqcp_provider.so /usr/local/lib/
sudo ldconfig

echo "动态链接库配置完成。"
echo ""

# --- 完成 ---
echo "======================================================="
echo " 环境依赖安装成功!"
echo " 所有第三方库已安装在 'third_party' 目录下。"
echo "======================================================="

# 返回到项目根目录
cd ../..

# 7. 测试
gcc -fdiagnostics-color=always -g \
    -I/usr/local/include/hitls -I/usr/local/include/hitls/auth \
    -I/usr/local/include/hitls/bsl -I/usr/local/include/hitls/crypto \
    -I/usr/local/include/hitls/pki -I/usr/local/include/hitls/tls \
    -L/usr/local/lib -Wl,-rpath=/usr/local/lib \
    test.c \
    -lhitls_crypto -lhitls_bsl -lhitls_tls -lboundscheck -lpthread \
    -o test

./test
