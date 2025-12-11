# 基于 Python 3.11 slim 镜像（使用国内镜像源加速）
FROM docker.1ms.run/python:3.11-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    DEBIAN_FRONTEND=noninteractive

# 锁定 Debian 版本并显式安装依赖
RUN echo "deb https://mirrors.aliyun.com/debian bullseye main" > /etc/apt/sources.list && \
    echo "deb https://mirrors.aliyun.com/debian-security bullseye-security main" >> /etc/apt/sources.list && \
    rm -rf /etc/apt/sources.list.d/* && \
    apt-get update --allow-releaseinfo-change && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    gnupg \
    lsb-release \
    perl-base=5.32.1-4+deb11u4 \
    libncurses6=6.2+20201114-2+deb11u2 && \
    echo "安装 MySQL" && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    default-mysql-server \
    default-mysql-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    echo "验证国内源是否生效：" && grep -E "mirrors.aliyun.com" /etc/apt/sources.list

# 使用最新版本，或根据需要固定为 3.6.0
ARG NUCLEI_VERSION=3.6.0
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        NUCLEI_ARCH="linux_amd64"; \
    elif [ "$ARCH" = "arm64" ]; then \
        NUCLEI_ARCH="linux_arm64"; \
    elif [ "$ARCH" = "armhf" ]; then \
        # 注意：3.6.0版本中 arm 架构命名为 `linux_arm.zip`
        NUCLEI_ARCH="linux_arm"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    # 使用加速镜像下载
    wget -q https://gh-proxy.org/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip \
    && unzip nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip -d /usr/local/bin/ \
    && rm nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip \
    && chmod +x /usr/local/bin/nuclei

# 复制依赖文件并安装（使用清华源加速）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 复制应用代码和配置
COPY app.py .
COPY config.py .
COPY static/ static/
COPY templates/ templates/

# 创建必要目录
RUN mkdir -p bin nuclei_rules scan_results data /var/run/mysqld /var/lib/mysql
RUN chown -R mysql:mysql /var/run/mysqld /var/lib/mysql

# 创建符号链接使应用能找到 nuclei
RUN ln -s /usr/local/bin/nuclei /app/bin/nuclei

# 复制启动脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 暴露端口
EXPOSE 5001

# 健康检查支持 HTTP 和 HTTPS（修复 protocol 未设置警告）
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD protocol=$(python3 -c "import config; print('https' if getattr(config, 'HTTPS_ENABLED', False) else 'http')") && \
    wget --no-verbose --tries=1 --spider $protocol://localhost:5001/ || exit 1

# 启动命令
ENTRYPOINT ["/entrypoint.sh"]
