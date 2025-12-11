# 基于 Python 3.11 slim 镜像（使用国内镜像源加速）
FROM docker.1ms.run/python:3.11-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 下载并安装 Nuclei (自动检测架构，使用 gh-proxy 加速)
ARG NUCLEI_VERSION=3.3.7
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        NUCLEI_ARCH="linux_amd64"; \
    elif [ "$ARCH" = "arm64" ]; then \
        NUCLEI_ARCH="linux_arm64"; \
    elif [ "$ARCH" = "armhf" ]; then \
        NUCLEI_ARCH="linux_armv6"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -q https://gh-proxy.org/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip \
    && unzip nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip -d /usr/local/bin/ \
    && rm nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip \
    && chmod +x /usr/local/bin/nuclei

# 复制依赖文件并安装（使用清华源加速）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 复制应用代码
COPY app.py .
COPY static/ static/
COPY templates/ templates/

# 创建必要目录
RUN mkdir -p bin nuclei_rules scan_results data

# 创建符号链接使应用能找到 nuclei
RUN ln -s /usr/local/bin/nuclei /app/bin/nuclei

# 暴露端口
EXPOSE 5001

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5001/ || exit 1

# 启动命令
CMD ["python", "app.py"]
