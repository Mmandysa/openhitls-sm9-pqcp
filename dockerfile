# ==============================================================================
# openhitls_sm9_pqcp Dockerfile
# 基于 Ubuntu 22.04 构建包含 GmSSL、PQCP 和 openHiTLS 的完整环境
# ==============================================================================

# 第一阶段：构建环境
FROM ubuntu:22.04 AS builder

# 避免交互式提示
ENV DEBIAN_FRONTEND=noninteractive

# 1. 安装系统依赖
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    cmake \
    make \
    libssl-dev \
    python3-pip \
    autoconf \
    automake \
    libtool \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 2. 创建工作目录
WORKDIR /project
COPY . .

# 3. 安装 GmSSL
RUN cd third_party && \
    git clone https://gitee.com/rootgd/GmSSL.git && \
    cd GmSSL && \
    mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# 4. 安装 PQCP
RUN cd third_party && \
    git clone https://gitcode.com/openHiTLS/pqcp.git && \
    cd pqcp && \
    chmod +x build_pqcp.sh && \
    ./build_pqcp.sh && \
    cp build/libpqcp_provider.so /usr/local/lib/ && \
    ldconfig

# 5. 安装 Secure_C 库
RUN cd third_party/pqcp/platform/openhitls/platform/Secure_C && \
    make && \
    cp lib/libboundscheck.so /usr/local/lib/ && \
    ldconfig

# 6. 配置头文件
RUN mkdir -p /usr/local/include/pqcp && \
    cp third_party/pqcp/include/*.h /usr/local/include/pqcp/ && \
    mkdir -p /usr/local/include/hitls && \
    find third_party/pqcp/platform/openhitls/include -mindepth 1 -maxdepth 1 -type d -exec cp -r {} /usr/local/include/hitls/ \; && \
    cp third_party/pqcp/platform/openhitls/build/*.so /usr/local/lib

# 第二阶段：生成轻量级运行时镜像
FROM ubuntu:22.04

# 1. 仅安装运行时依赖
RUN apt-get update && apt-get install -y \
    libssl3 \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 2. 从构建阶段复制必要的文件
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/include /usr/local/include
COPY --from=builder /project /project

# 3. 配置动态链接库
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && \
    ldconfig

# 4. 设置工作目录
WORKDIR /project

# 5. 验证安装
RUN ls -l /usr/local/lib/libpqcp* && \
    ls -l /usr/local/lib/libboundscheck* && \
    ls -l /usr/local/include/pqcp/

# 6. 设置默认命令（可根据需要修改）
CMD ["bash"]