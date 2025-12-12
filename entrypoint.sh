#!/bin/bash
set -e

echo "=========================================="
echo "NucLens 启动脚本"
echo "=========================================="

# 启动 Flask 应用
echo "启动 NucLens 应用..."
exec python app.py
