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

### 方式一：本地部署

```bash
# 克隆项目
git clone https://github.com/d1a0/NucLens.git
cd NucLens

# 安装依赖
pip install -r requirements.txt

# 下载 Nuclei 放入 bin/ 目录
# https://github.com/projectdiscovery/nuclei/releases

# 启动
python app.py
```

### 方式二：Docker Compose（推荐）

```bash
docker-compose up -d
```

### 方式三：Docker

```bash
# 构建镜像
docker build -t nuclens .

# 运行容器
docker run -d -p 5001:5001 --name nuclens nuclens
```

---

访问 http://localhost:5001，默认账户：`admin` / `admin`

> ⚠️ 首次登录请修改默认密码

## 📁 项目结构

```
NucLens/
├── app.py              # 主程序
├── requirements.txt    # 依赖
├── Dockerfile
├── docker-compose.yml
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
2. 生产环境修改 `JWT_SECRET_KEY`
3. 建议内网部署
4. 定期备份 `app.db`

## 📄 许可证

[MIT License](LICENSE)

## 🙏 致谢

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 漏洞扫描引擎
- [Flask](https://flask.palletsprojects.com/) - Web 框架
