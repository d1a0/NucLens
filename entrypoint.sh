#!/bin/bash
set -e

# 从 config.py 读取数据库配置
MYSQL_USER=$(python3 -c "import config; print(config.MYSQL_USER)" 2>/dev/null || echo "root")
MYSQL_PASSWORD=$(python3 -c "import config; print(config.MYSQL_PASSWORD)" 2>/dev/null || echo "123456")
MYSQL_DATABASE=$(python3 -c "import config; print(config.MYSQL_DATABASE)" 2>/dev/null || echo "nuclens")

echo "=========================================="
echo "NucLens 启动脚本"
echo "=========================================="

# 初始化 MySQL 数据目录（如果未初始化）
if [ ! -d "/var/lib/mysql/mysql" ]; then
    echo "[1/4] 初始化 MySQL 数据库..."
    mysqld --initialize-insecure --user=mysql --datadir=/var/lib/mysql
else
    echo "[1/4] MySQL 数据目录已存在，跳过初始化"
fi

# 启动 MySQL 服务
echo "[2/4] 启动 MySQL 服务..."
mysqld --user=mysql --datadir=/var/lib/mysql &

# 等待 MySQL 启动完成
echo "[3/4] 等待 MySQL 启动..."
MAX_TRIES=30
TRIES=0
while ! mysqladmin ping -h localhost --silent 2>/dev/null; do
    TRIES=$((TRIES + 1))
    if [ $TRIES -ge $MAX_TRIES ]; then
        echo "错误: MySQL 启动超时"
        exit 1
    fi
    sleep 1
done
echo "MySQL 启动成功!"

# 配置 MySQL 用户和数据库
echo "[4/4] 配置数据库..."
mysql -u root <<-EOSQL
    -- 创建数据库（如果不存在）
    CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    
    -- 设置 root 密码并授权
    ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_PASSWORD}';
    FLUSH PRIVILEGES;
EOSQL

echo "=========================================="
echo "数据库配置完成!"
echo "数据库: ${MYSQL_DATABASE}"
echo "用户: ${MYSQL_USER}"
echo "=========================================="

# 启动 Flask 应用
echo "启动 NucLens 应用..."
exec python app.py
