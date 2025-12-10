# NucLens

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Flask-2.0+-green.svg" alt="Flask">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

**NucLens** 是一个基于 [Nuclei](https://github.com/projectdiscovery/nuclei) 的漏洞扫描管理框架，提供了 Web 界面来管理扫描规则、执行扫描任务和查看扫描结果。

## ✨ 功能特性

- 🔐 **用户认证系统**：支持管理员、编辑、普通用户三种角色，带有注册审核机制
- 📝 **规则管理**：上传、验证、发布 YAML 规则，支持标签分类
- 📦 **批量操作**：批量导入/导出规则（ZIP格式），批量验证、发布、删除
- 🔍 **漏洞扫描**：基于标签选择规则，执行目标扫描
- 📊 **结果展示**：查看扫描历史和详细漏洞报告
- ⚙️ **系统设置**：支持上传自定义 Nuclei 二进制文件，兼容 Windows/Linux/macOS
- 👤 **个人中心**：用户可自行修改密码

## 🚀 快速开始

### 环境要求

- Python 3.8+
- Nuclei（可通过系统设置上传）

### 本地安装

1. **克隆项目**
```bash
git clone https://github.com/yourusername/NucLens.git
cd NucLens
```

2. **安装依赖**
```bash
pip install -r requirements.txt
```

3. **下载 Nuclei**

从 [Nuclei Releases](https://github.com/projectdiscovery/nuclei/releases) 下载对应系统的版本，放入 `bin/` 目录：
- Windows: `bin/nuclei.exe`
- Linux/macOS: `bin/nuclei`

4. **启动应用**
```bash
python app.py
```

5. **访问系统**

打开浏览器访问 `http://localhost:5001`

默认管理员账户：
- 用户名：`admin`
- 密码：`admin`

> ⚠️ 首次登录后请立即修改默认密码！

### Docker 部署

1. **构建镜像**
```bash
docker build -t nuclens .
```

2. **运行容器**
```bash
docker run -d -p 5001:5001 --name nuclens nuclens
```

3. **使用 Docker Compose**
```bash
docker-compose up -d
```

## 📁 项目结构

```
NucLens/
├── app.py              # 主应用程序
├── requirements.txt    # Python 依赖
├── Dockerfile          # Docker 构建文件
├── docker-compose.yml  # Docker Compose 配置
├── .gitignore          # Git 忽略文件
├── bin/                # Nuclei 二进制文件目录
├── nuclei_rules/       # 规则文件存储目录
├── scan_results/       # 扫描结果存储目录
├── static/
│   ├── css/
│   │   └── style.css   # 样式文件
│   └── js/
│       └── app.js      # 前端逻辑
└── templates/
    └── index.html      # 主页面模板
```

## 🔧 配置说明

### 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `JWT_SECRET_KEY` | JWT 密钥 | 内置默认值（生产环境请修改） |
| `DATABASE_URL` | 数据库连接 | `sqlite:///app.db` |

### 用户角色

| 角色 | 权限 |
|------|------|
| `admin` | 全部权限：用户管理、系统设置、规则管理、扫描 |
| `editor` | 规则上传、验证、发布、扫描 |
| `user` | 查看规则、执行扫描 |

## 📖 使用指南

### 规则管理

1. **上传规则**：支持单文件上传或直接粘贴 YAML 内容
2. **验证规则**：使用 Nuclei 验证规则语法
3. **发布规则**：验证通过后可发布规则供扫描使用
4. **标签管理**：为规则添加标签便于分类

### 批量操作

- **导出**：选择规则导出为 ZIP 文件（包含 `rules_meta.json` 保存标签信息）
- **导入**：上传 ZIP 文件批量导入规则
- **批量验证/发布/删除**：选择多个规则进行批量操作

### 执行扫描

1. 输入目标 URL
2. 选择要使用的规则标签
3. 提交扫描任务
4. 在扫描历史中查看结果

## 🔒 安全建议

1. **修改默认密码**：首次登录后立即修改 admin 密码
2. **修改 JWT 密钥**：在生产环境中修改 `JWT_SECRET_KEY`
3. **网络隔离**：建议在内网环境部署
4. **定期备份**：备份 `app.db` 数据库文件

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源许可证。

## 🙏 致谢

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 强大的漏洞扫描引擎
- [Flask](https://flask.palletsprojects.com/) - Python Web 框架
