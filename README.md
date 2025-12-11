# NucLens

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Flask-2.0+-green.svg" alt="Flask">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/AI-Powered-purple.svg" alt="AI Powered">
</p>

<p align="center">
  基于 <a href="https://github.com/projectdiscovery/nuclei">Nuclei</a> 的漏洞扫描管理框架
</p>

> 🤖 **本项目代码由 AI (Claude) 全程辅助编写**

---

## ✨ 功能特性

- 🔐 **用户认证** - 管理员/编辑/用户三种角色，注册审核机制
- 📝 **规则管理** - 上传、验证、发布 YAML 规则，标签分类
- 📦 **批量操作** - ZIP 格式导入导出，批量验证/发布/删除
- 🔍 **漏洞扫描** - 按标签选择规则，执行目标扫描
- 📊 **结果查看** - 扫描历史和详细漏洞报告
- ⚙️ **系统设置** - 上传 Nuclei 二进制，支持 Windows/Linux/macOS
- 👤 **个人中心** - 用户自行修改密码

## 🚀 部署方式

### 方式一：Docker Compose（推荐）

```bash
# 克隆项目
git clone https://github.com/d1a0/NucLens.git
cd NucLens

# 启动服务
docker-compose up -d
```

> ✅ **开箱即用**：Docker 镜像已内置 MySQL 数据库，无需额外配置，启动即可使用。

**可选配置**：如需自定义，编辑 `config.py` 文件

```python
# JWT 密钥（留空则自动生成，重启后 token 失效）
JWT_SECRET_KEY = 'your-secret-key'

# 应用端口
APP_PORT = 5001

# HTTPS 配置（可选）
HTTPS_ENABLED = False
SSL_CERT_PATH = 'certs/cert.pem'
SSL_KEY_PATH = 'certs/key.pem'
```

### 方式二：Docker

```bash
# 克隆项目
git clone https://github.com/d1a0/NucLens.git
cd NucLens

# 构建镜像
docker build -t nuclens .

# 运行容器
docker run -d -p 5001:5001 --name nuclens \
  -v $(pwd)/config.py:/app/config.py \
  -v $(pwd)/nuclei_rules:/app/nuclei_rules \
  -v $(pwd)/scan_results:/app/scan_results \
  -v nuclens_mysql:/var/lib/mysql \
  nuclens
```

### 方式三：本地部署

```bash
# 克隆项目
git clone https://github.com/d1a0/NucLens.git
cd NucLens

# 安装依赖
pip install -r requirements.txt

# 安装并启动 MySQL（需手动安装）
# 创建数据库：CREATE DATABASE nuclens CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# 修改 config.py 配置数据库连接
vim config.py

# 下载 Nuclei 放入 bin/ 目录（可选，也可在系统设置中上传）
# https://github.com/projectdiscovery/nuclei/releases

# 启动
python app.py
```

> 💡 数据库表会在首次启动时自动创建

---

访问 http://localhost:5001，默认账户：admin / admin

> ⚠️ 首次登录请修改默认密码

## 📁 项目结构

```
NucLens/
├── app.py              # 主程序
├── config.py           # 配置文件（数据库、JWT等）
├── requirements.txt    # 依赖
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh       # Docker 启动脚本
├── bin/                # Nuclei 二进制
├── nuclei_rules/       # 规则存储
├── scan_results/       # 扫描结果
├── static/             # 前端资源
└── templates/          # 页面模板
```

## 🔧 用户角色

| 角色 | 权限 |
|------|------|
| admin | 全部权限：用户管理、系统设置、规则管理、扫描 |
| editor | 规则上传、验证、发布、扫描 |
| user | 查看规则、执行扫描 |

## 🔒 安全建议

1. 修改默认 admin 密码
2. 修改 `config.py` 中的 `JWT_SECRET_KEY` 和 `MYSQL_PASSWORD`
3. 建议内网部署
4. 定期备份 MySQL 数据

## 🔄 版本更新

### Docker Compose 更新（推荐）

```bash
cd NucLens
git pull
docker-compose up -d --build
```

> ✅ **数据安全**：docker-compose.yml 已配置 volume 持久化，更新不会丢失数据库、规则和扫描结果。

### Docker 更新

```bash
cd NucLens
git pull

# 停止并删除旧容器（不删除数据卷）
docker stop nuclens && docker rm nuclens

# 重新构建并运行
docker build -t nuclens .
docker run -d -p 5001:5001 --name nuclens \
  -v $(pwd)/config.py:/app/config.py \
  -v $(pwd)/nuclei_rules:/app/nuclei_rules \
  -v $(pwd)/scan_results:/app/scan_results \
  -v nuclens_mysql:/var/lib/mysql \
  nuclens
```

### 本地部署更新

```bash
cd NucLens
git pull
pip install -r requirements.txt  # 如有新依赖
python app.py
```

### 数据持久化说明

| 数据 | 存储位置 | 说明 |
|------|----------|------|
| 数据库 | MySQL `/var/lib/mysql` | 用户、规则元数据、扫描任务 |
| 配置文件 | `config.py` | 数据库连接、JWT密钥等 |
| 规则文件 | `nuclei_rules/` | YAML 规则文件 |
| 扫描结果 | `scan_results/` | JSON 格式扫描报告 |
| Nuclei | `bin/` | 扫描引擎二进制 |

## 📄 许可证

[MIT License](LICENSE)

## 🙏 致谢

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 漏洞扫描引擎
- [Flask](https://flask.palletsprojects.com/) - Web 框架
