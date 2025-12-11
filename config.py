# -*- coding: utf-8 -*-
"""
NucLens 配置文件
请根据实际环境修改以下配置
"""

# ============ 版本信息 ============
VERSION = '2.0.3'

# ============ 数据库配置 ============
# MySQL 连接配置
MYSQL_HOST = 'localhost'      # 数据库主机地址
MYSQL_PORT = 3306             # 数据库端口
MYSQL_USER = 'root'           # 数据库用户名
MYSQL_PASSWORD = '123456'     # 数据库密码
MYSQL_DATABASE = 'nuclens'    # 数据库名称

# ============ 安全配置 ============
# JWT 密钥（留空则自动生成随机密钥，重启后token失效）
# 生产环境建议设置固定值
JWT_SECRET_KEY = ''

# ============ 应用配置 ============
# 应用端口
APP_PORT = 5001
# 调试模式（生产环境请设为 False）
DEBUG_MODE = False
