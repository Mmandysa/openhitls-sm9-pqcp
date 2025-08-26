#!/bin/bash




THIRD_PARTY_DIR="$PWD/third_party"
PQCP_DIR="$THIRD_PARTY_DIR/pqcp"
OPENHITLS_DIR="$PQCP_DIR/platform/openhitls"
Secure_C_DIR="$OPENHITLS_DIR/platform/Secure_C"

#安装依赖包
sudo apt update
echo "--- [1/5] 正在安装核心依赖 (gcc, cmake, make, libssl-dev, etc.)... ---"
sudo apt install gcc cmake make libssl-dev python3-pip autoconf automake libtool -y
echo "核心依赖安装完成。"




# 检查目录是否存在
echo "--- [2/5] 检查当前目录结构... ---"
if [ -d "$THIRD_PARTY_DIR" ]; then
    echo "$THIRD_PARTY_DIR 目录已存在"
else
    echo "目录不存在，正在创建: $THIRD_PARTY_DIR"
    mkdir -p "$THIRD_PARTY_DIR"
    if [ $? -eq 0 ]; then
        echo "创建成功"
    else
        echo "创建失败，请检查权限" >&2
        exit 1
    fi
fi
echo "目录结构正确，进入 'third_party' 目录开始安装。"
cd "$THIRD_PARTY_DIR"




# 克隆并安装 GmSSL
echo "--- [3/5] 正在克隆并安装 GmSSL... ---"
if [ -d "GmSSL" ]; then
    echo "GmSSL 目录已存在"
else
    echo "正在克隆 GmSSL 仓库..."
    git clone https://gitee.com/rootgd/GmSSL.git
    if [ $? -eq 0 ]; then
        echo "克隆成功"
    else
        echo "克隆失败，请检查网络连接" >&2
        exit 1
    fi
fi

echo "正在安装 GmSSL..."
cd GmSSL
mkdir -p build
cd build
cmake ..
make
make test
sudo make install
if [ $? -eq 0 ]; then
    echo "GmSSL 安装成功"
else
    echo "GmSSL 安装失败" >&2
    exit 1
fi
cd "$THIRD_PARTY_DIR"


# --- 4. 安装 PQCP 组件 ---
echo "--- [4/5] 正在克隆并构建 PQCP 组件... ---"
if [ -d "pqcp" ];then 
    echo "pqcp 目录已存在"
else
    echo "正在克隆 pqcp 仓库..."
    git clone https://gitcode.com/openHiTLS/pqcp.git
    if [ $? -eq 0 ]; then
        echo "PQCP 克隆成功"
    else
        echo "PQCP 克隆失败，请检查网络连接" >&2
        exit 1
    fi
fi

echo "正在构建 PQCP 组件..."
cd pqcp
sudo bash ./build_pqcp.sh
cd $OPENHITLS_DIR/build && sudo make install
if [ $? -eq 0 ]; then
    echo "PQCP 组件构建成功"
else
    echo "PQCP 组件构建失败" >&2
    exit 1
fi
cd "$THIRD_PARTY_DIR"

# --- 5. 配置动态链接库 ---
echo "--- [5/5] 正在配置系统动态链接库... ---"
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/local.conf > /dev/null

sudo cp $Secure_C_DIR/lib/*.so /usr/local/lib/
if [ $? -eq 0 ]; then
    echo "Secure_C 动态库安装成功"
else
    echo "Secure_C 动态库安装失败" >&2
    exit 1
fi

sudo mkdir -p /usr/local/include/pqcp && sudo cp $PQCP_DIR/include/*.h /usr/local/include/pqcp/ && sudo cp $PQCP_DIR/src/provider/*.h /usr/local/include/pqcp/ 
sudo mkdir -p /usr/local/include/scloudplus && sudo cp $PQCP_DIR/scloudplus/src/*.h /usr/local/include/scloudplus/ && sudo cp $PQCP_DIR/scloudplus/include/*.h /usr/local/include/scloudplus/
sudo cp $PQCP_DIR/build/libpqcp_provider.so /usr/local/lib/
if [ $? -eq 0 ]; then
    echo "PQCP 安装成功"
else
    echo "PQCP 安装失败" >&2
    exit 1
fi
sudo ldconfig

echo "动态链接库配置完成。"
echo ""
# --- 完成 ---
echo "======================================================="
echo " 环境依赖安装成功!"
echo " 所有第三方库已安装在 'third_party' 目录下。"
echo "======================================================="
