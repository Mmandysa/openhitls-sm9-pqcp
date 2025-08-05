#!/bin/bash

# ==============================================================================
#  SM9-PQCP 项目依赖安装脚本 (项目内运行版)
# ==============================================================================
#
#  功能:
#  1. 更新系统并安装 Git.
#  2. 配置 Git 用户信息 (请手动修改).
#  3. 安装项目所需的编译工具和依赖库.
#  4. 自动从 Gitee/GitCode 克隆、编译和安装 GmSSL, openHiTLS, PQCP.
#  5. 配置系统动态链接库路径.
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

# --- 1. Git 安装与配置 ---
echo "--- [1/6] 正在安装并配置 Git... ---"
sudo apt update
sudo apt install git -y
echo "Git 安装完成，版本信息如下:"
git --version

# ******************************************************************************
# * 重要: 请将下面的 "Your Name" 和 "useremail" 替换成您自己的 Git 用户名和邮箱 *
# ******************************************************************************
git config --global user.name "Your Name"
git config --global user.email "useremail"
echo "Git 全局用户信息已配置。"
echo ""

# --- 2. 核心依赖安装 ---
echo "--- [2/6] 正在安装核心依赖 (gcc, cmake, make, libssl-dev, etc.)... ---"
sudo apt install gcc cmake make libssl-dev python3-pip autoconf automake libtool -y
echo "核心依赖安装完成。"
echo ""

# --- 检查脚本位置 ---
echo "--- [3/6] 检查当前目录结构... ---"
if [ ! -d "third_party" ] || [ ! -d "src" ]; then
    echo "错误: 未找到 'third_party' 或 'src' 目录。"
    echo "请确保此脚本位于 'openhitls_sm9_pqcp' 项目根目录下运行。"
    exit 1
fi
echo "目录结构正确，进入 'third_party' 目录开始安装。"
cd third_party
echo ""


# --- 4. 安装 GmSSL ---
echo "--- [4/6] 正在克隆并安装 GmSSL... ---"
git clone https://gitee.com/rootgd/GmSSL.git
cd GmSSL
mkdir -p build
cd build
cmake ..
make
# 'make test' 会运行测试，可能会花费一些时间，默认注释掉。如果需要，可以取消注释。
# make test
sudo make install
cd ../.. # 返回到 third_party 目录
echo "GmSSL 安装完成。"
echo ""

# --- 5. 安装 openHiTLS ---
echo "--- [5/6] 正在克隆并安装 openHiTLS... ---"
git clone --recurse-submodules https://gitcode.com/openhitls/openhitls.git
cd openhitls

echo "--> 正在编译和安装 openHiTLS 的 Secure_C 平台..."
cd platform/Secure_C
make
sudo make install
cd ../.. # 返回到 openhitls 根目录

echo "--> 正在编译和安装 openHiTLS 主程序..."
mkdir -p build
cd build
cmake ..
make
sudo make install
cd ../.. # 返回到 third_party 目录
echo "openHiTLS 安装完成。"
echo ""

# --- 6. 安装 PQCP 组件 ---
echo "--- [6/6] 正在克隆并构建 PQCP 组件... ---"
git clone https://gitcode.com/openHiTLS/pqcp.git

echo "--> 正在自动替换 PQCP 的 CMakeLists.txt 文件..."
# 根据用户指示，从 third_party 目录将预先准备好的 CMakeLists.txt.txt
# 复制并重命名到 pqcp 目录下，以替换其默认配置。
# 请确保在运行此脚本前，已将名为 CMakeLists.txt.txt 的文件放置在 'third_party' 目录下。
cp ./CMakeLists.txt.txt ./pqcp/CMakeLists.txt

cd pqcp
mkdir -p build
cd build
cmake ..
make
cd ../.. # 返回到 third_party 目录
echo "PQCP 组件构建完成。"
echo ""

# --- 7. 配置动态链接库 ---
echo "--- [7/7] 正在配置系统动态链接库... ---"
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/local.conf > /dev/null
sudo cp ./openhitls/platform/Secure_C/lib/libboundscheck.so /usr/local/lib/
sudo ldconfig
echo "动态链接库配置完成。"
echo ""

# --- 完成 ---
echo "======================================================="
echo " 环境依赖安装成功!"
echo " 所有第三方库已安装在 'third_party' 目录下。"
echo "======================================================="

# 返回到项目根目录
cd ..