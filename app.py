# -*- coding: utf-8 -*-

# 版本号
__version__ = '2.0.8'

import os
import subprocess
import threading
import json
import zipfile
import io
import tempfile
import secrets
import ipaddress
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, render_template, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, JWTManager, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import yaml
import platform

# App initialization
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
# 数据目录（用于持久化数据库等）
datadir = os.path.join(basedir, 'data')
os.makedirs(datadir, exist_ok=True)
# 默认 Nuclei 可执行文件路径（会被系统设置覆盖）
if platform.system() == 'Windows':
    DEFAULT_NUCLEI_PATH = os.path.join(basedir, 'bin', 'nuclei.exe')
else:
    DEFAULT_NUCLEI_PATH = os.path.join(basedir, 'bin', 'nuclei')
# Nuclei 二进制文件上传目录
NUCLEI_BIN_FOLDER = os.path.join(basedir, 'bin')

# 加载配置文件
try:
    import config
    MYSQL_HOST = getattr(config, 'MYSQL_HOST', 'localhost')
    MYSQL_PORT = getattr(config, 'MYSQL_PORT', 3306)
    MYSQL_USER = getattr(config, 'MYSQL_USER', 'root')
    MYSQL_PASSWORD = getattr(config, 'MYSQL_PASSWORD', '123456')
    MYSQL_DATABASE = getattr(config, 'MYSQL_DATABASE', 'nuclens')
    JWT_SECRET = getattr(config, 'JWT_SECRET_KEY', '')
except ImportError:
    # 配置文件不存在时使用默认值
    MYSQL_HOST = 'localhost'
    MYSQL_PORT = 3306
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = '123456'
    MYSQL_DATABASE = 'nuclens'
    JWT_SECRET = ''

# 动态设置 MySQL 主机地址
if os.path.exists('/.dockerenv'):
    MYSQL_HOST = 'mysql'  # Docker 容器内使用容器名
else:
    MYSQL_HOST = 'localhost'  # 本地运行使用 localhost

# MySQL 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}
# JWT密钥：优先使用配置文件，否则自动生成随机密钥
app.config['JWT_SECRET_KEY'] = JWT_SECRET or secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'nuclei_rules')
app.config['SCAN_RESULTS_FOLDER'] = os.path.join(basedir, 'scan_results')

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- Models ---
class User(db.Model):
    """用户模型"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='user')
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved, rejected
    must_change_password = db.Column(db.Boolean, default=False)  # 是否需要修改密码
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """设置密码，使用哈希加密"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """校验密码"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'status': self.status,
            'must_change_password': self.must_change_password,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<User {self.username}>'

# Association Table for YamlRule and Tag
rule_tags = db.Table('rule_tags',
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True),
    db.Column('rule_id', db.Integer, db.ForeignKey('yaml_rule.id'), primary_key=True)
)

class YamlRule(db.Model):
    """YAML 规则模型"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(191), nullable=False, unique=True)  # 191 for MySQL utf8mb4 index limit
    file_path = db.Column(db.String(500), nullable=False)
    uploaded_by = db.Column(db.String(80), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    # 状态: pending (待验证), verified (已验证), published (已公开), failed (验证失败)
    status = db.Column(db.String(50), nullable=False, default='pending')
    tags = db.relationship('Tag', secondary=rule_tags, lazy='subquery',
        backref=db.backref('rules', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'file_path': self.file_path,
            'status': self.status, # <--- THE FIX IS HERE
            'uploaded_by': self.uploaded_by,
            'uploaded_at': self.uploaded_at.isoformat(),
            'tags': [tag.name for tag in self.tags]
        }

class Tag(db.Model):
    """标签模型"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class SystemSettings(db.Model):
    """系统设置模型"""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get(key, default=None):
        """获取设置值"""
        setting = SystemSettings.query.filter_by(key=key).first()
        return setting.value if setting else default
    
    @staticmethod
    def set(key, value):
        """设置值"""
        setting = SystemSettings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = SystemSettings(key=key, value=value)
            db.session.add(setting)
        db.session.commit()
        return setting

# --- ScanTask Model ---
class ScanTask(db.Model):
    """扫描任务模型"""
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    tags = db.Column(db.String(255), nullable=False)  # 逗号分隔的标签字符串
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, error
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    result_file_path = db.Column(db.String(255), nullable=True)
    error_log = db.Column(db.Text, nullable=True)
    findings_summary = db.Column(db.Text, nullable=True) # 存储发现的 template-id 列表

    def to_dict(self):
        # 安全解析 findings_summary
        findings = None
        if self.findings_summary and self.findings_summary.strip():
            try:
                findings = json.loads(self.findings_summary)
            except json.JSONDecodeError:
                findings = None
        
        return {
            'id': self.id,
            'target_url': self.target_url,
            'tags': self.tags.split(',') if self.tags else [],
            'status': self.status,
            'initiated_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'result_file_path': self.result_file_path,
            'error_log': self.error_log,
            'findings_summary': findings
        }

# --- Helper Functions ---
def get_nuclei_path():
    """获取当前配置的 nuclei 路径"""
    # 优先使用数据库中的设置
    try:
        custom_path = SystemSettings.get('nuclei_path')
        if custom_path and os.path.isfile(custom_path):
            return custom_path
    except:
        pass
    # 回退到默认路径
    return DEFAULT_NUCLEI_PATH

# --- Background Scan Function ---
def run_scan(task_id, app_context):
    """在后台线程中运行 nuclei 扫描"""
    with app_context:
        # 使用新的 db.session.get() 方法，并修复了命令构建逻辑
        task = db.session.get(ScanTask, task_id)
        if not task:
            return

        task.status = 'running'
        db.session.commit()

        result_filename = f"scan_{task.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        result_filepath = os.path.join(app.config['SCAN_RESULTS_FOLDER'], result_filename)

        # 确保输出目录存在
        os.makedirs(app.config['SCAN_RESULTS_FOLDER'], exist_ok=True)

        tags_list = task.tags.split(',')
        rules_to_run = set()
        rules = YamlRule.query.join(YamlRule.tags).filter(
            YamlRule.status == 'published',
            Tag.name.in_(tags_list)
        ).all()

        for rule in rules:
            if os.path.exists(rule.file_path):
                rules_to_run.add(rule.file_path)

        if not rules_to_run:
            task.status = 'error'
            task.error_log = f"错误: 找不到与标签 {task.tags} 关联的已公开规则文件。"
            db.session.commit()
            print(task.error_log)
            return

        # --- 正确的命令构建逻辑 ---
        nuclei_path = get_nuclei_path()
        
        # 构建模板参数：逗号分隔的模板路径列表
        template_args = ','.join(rules_to_run)
        
        command = [
            nuclei_path,
            '-u', task.target_url,
            '-jsonl',
            '-o', result_filepath,
            '-t', template_args  # 使用 -t 参数指定逗号分隔的模板路径
        ]
        
        print(f"构建的 nuclei 命令: {' '.join(command)}")
        print(f"模板参数: {template_args}")

        try:
            # 添加超时设置，避免扫描卡住
            result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8', timeout=300)  # 5分钟超时
            task.status = 'completed'
            task.result_file_path = result_filepath

            # 解析结果并存储 findings_summary 为 JSON 格式
            findings_count = 0
            found_templates = set()
            with open(result_filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        finding = json.loads(line)
                        if 'template-id' in finding:
                            found_templates.add(finding['template-id'])
                            findings_count += 1
                    except json.JSONDecodeError:
                        continue
            # 保存为 JSON 字符串
            task.findings_summary = json.dumps({
                'total': findings_count,
                'templates': sorted(list(found_templates))
            })

        except subprocess.TimeoutExpired:
            task.status = 'error'
            task.error_log = "错误: 扫描超时（5分钟）。"
            print(f"扫描任务 {task.id} 超时")
        except FileNotFoundError:
            task.status = 'error'
            task.error_log = "错误: 'nuclei' 命令未找到。请确保 bin/nuclei.exe 存在。"
            print(task.error_log)
        except subprocess.CalledProcessError as e:
            task.status = 'error'
            # 同时捕获 stdout 和 stderr
            error_output = f"Nuclei exited with a non-zero status.\n--- STDOUT ---\n{e.stdout}\n--- STDERR ---\n{e.stderr}"
            task.error_log = error_output
            print(f"运行 nuclei 扫描任务 {task.id} 时出错:\n{error_output}")
        except Exception as e:
            task.status = 'error'
            task.error_log = str(e)
            print(f"扫描任务 {task.id} 发生意外错误: {e}")

        db.session.commit()

def parse_nuclei_output(result_filepath):
    """解析 Nuclei JSON 输出文件并返回结构化数据"""
    vulnerabilities = []
    try:
        with open(result_filepath, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    finding = json.loads(line)
                    vulnerabilities.append({
                        "template-id": finding.get("template-id"),
                        "severity": finding.get("info", {}).get("severity"),
                        "matched-at": finding.get("matched-at"),
                        "description": finding.get("info", {}).get("description"),
                    })
                except json.JSONDecodeError:
                    # 忽略空行或格式错误的行
                    continue
        return {
            "has_vulnerability": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities
        }
    except FileNotFoundError:
        # 返回一个元组，表示错误和状态码
        return ({"msg": "结果文件未找到。"}, 404)
    except Exception as e:
        return ({"msg": f"读取或解析结果文件时出错: {e}"}, 500)

# --- Decorators ---
def role_required(required_roles):
    """
    自定义装饰器，用于验证用户角色权限
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            current_user_identity = get_jwt_identity()
            user = User.query.filter_by(username=current_user_identity).first()
            if not user or user.role not in required_roles:
                return jsonify({"msg": "Forbidden: Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# --- API Endpoints ---
@app.route('/')
def index():
    """提供前端应用页面"""
    return render_template('index.html')

@app.route('/api/version')
def get_version():
    """获取系统版本信息"""
    return jsonify({
        'version': __version__,
        'name': 'NucLens'
    })

@app.route('/api/register', methods=['POST'])
def register():
    """用户申请注册接口（需要管理员审核）"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "User already exists"}), 409 # Conflict

    # 只允许申请 user 和 editor 角色
    if role not in ['editor', 'user']:
        return jsonify({"msg": "只能申请普通用户或编辑者角色"}), 400

    new_user = User(username=username, role=role, status='pending')
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "注册申请已提交，请等待管理员审核"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    """用户登录接口"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"msg": "用户名或密码错误"}), 401
    
    if not user.check_password(password):
        return jsonify({"msg": "用户名或密码错误"}), 401
    
    # 检查用户状态
    if user.status == 'pending':
        return jsonify({"msg": "您的账户正在等待管理员审核"}), 403
    if user.status == 'rejected':
        return jsonify({"msg": "您的注册申请已被拒绝"}), 403
    
    # 在 access token 中添加角色信息
    additional_claims = {"role": user.role}
    access_token = create_access_token(identity=username, additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=username)
    return jsonify(
        access_token=access_token, 
        refresh_token=refresh_token, 
        role=user.role,
        must_change_password=user.must_change_password
    )


@app.route('/api/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """修改密码接口"""
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({"msg": "请提供旧密码和新密码"}), 400
    
    if len(new_password) < 6:
        return jsonify({"msg": "新密码长度至少6位"}), 400
    
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    if not user.check_password(old_password):
        return jsonify({"msg": "旧密码错误"}), 400
    
    user.set_password(new_password)
    user.must_change_password = False
    db.session.commit()
    
    return jsonify({"msg": "密码修改成功"})

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """获取当前用户个人资料"""
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    return jsonify(user.to_dict())

@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """更新当前用户个人资料（仅密码）"""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    # 修改密码
    if new_password:
        if not current_password:
            return jsonify({"msg": "请输入当前密码"}), 400
        
        if not user.check_password(current_password):
            return jsonify({"msg": "当前密码错误"}), 400
        
        if len(new_password) < 6:
            return jsonify({"msg": "新密码长度至少6位"}), 400
        
        user.set_password(new_password)
        user.must_change_password = False
        db.session.commit()
        return jsonify({"msg": "密码修改成功"})
    
    return jsonify({"msg": "没有要更新的内容"})

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """刷新 Access Token 接口"""
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token)

# --- YAML Rule Endpoints ---
@app.route('/api/yaml/upload', methods=['POST'])
@role_required(['admin', 'editor'])
def upload_yaml():
    """上传 YAML 规则文件，初始状态为 pending"""
    if 'file' not in request.files:
        return jsonify({"msg": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"msg": "No selected file"}), 400

    if not file or not file.filename.endswith(('.yaml', '.yml')):
        return jsonify({"msg": "Invalid file type, please upload a .yaml or .yml file"}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

    # 先保存文件
    file.save(filepath)

    try:
        # 独立的作用域来读取和解析文件，确保文件句柄被释放
        with open(filepath, 'r', encoding='utf-8') as f:
            yaml_content = yaml.safe_load(f)

        if not isinstance(yaml_content, dict):
            raise ValueError("Invalid YAML format: content is not a dictionary.")

        rule_id = yaml_content.get('id')
        if not rule_id:
            raise ValueError("YAML file must contain an 'id' field.")

        # 检查此规则 ID 是否已存在于数据库中
        if YamlRule.query.filter_by(name=rule_id).first():
            raise ValueError(f"A rule with the id '{rule_id}' already exists in the database.")

    except (yaml.YAMLError, ValueError) as e:
        # 如果解析或验证失败，删除已上传的文件
        os.remove(filepath)
        return jsonify({"msg": f"Error processing file: {e}"}), 400
    except Exception as e:
        # 捕获其他意外错误，例如权限问题
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({"msg": f"An unexpected error occurred during file processing: {e}"}), 500

    # 文件有效，创建数据库记录
    current_user = get_jwt_identity()
    new_rule = YamlRule(
        name=rule_id,
        file_path=filepath,
        uploaded_by=current_user,
        status='pending'  # 初始状态为待验证
    )

    db.session.add(new_rule)
    db.session.commit()

    return jsonify({"msg": "Rule uploaded successfully and is pending validation.", "rule": new_rule.to_dict()}), 201


@app.route('/api/yaml/upload-text', methods=['POST'])
@role_required(['admin', 'editor'])
def upload_yaml_text():
    """通过文本内容上传 YAML 规则（仅管理员和编辑可用）"""
    data = request.get_json()
    content = data.get('content')
    
    if not content:
        return jsonify({"msg": "No content provided"}), 400
    
    try:
        yaml_content = yaml.safe_load(content)
        
        if not isinstance(yaml_content, dict):
            raise ValueError("Invalid YAML format: content is not a dictionary.")
        
        rule_id = yaml_content.get('id')
        if not rule_id:
            raise ValueError("YAML content must contain an 'id' field.")
        
        # 检查此规则 ID 是否已存在于数据库中
        if YamlRule.query.filter_by(name=rule_id).first():
            raise ValueError(f"A rule with the id '{rule_id}' already exists in the database.")
        
        # 保存到文件
        filename = f"{rule_id}.yaml"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if os.path.exists(filepath):
            raise ValueError(f"A rule file with name '{filename}' already exists.")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # 创建数据库记录
        current_user = get_jwt_identity()
        new_rule = YamlRule(
            name=rule_id,
            file_path=filepath,
            uploaded_by=current_user,
            status='pending'
        )
        
        db.session.add(new_rule)
        db.session.commit()
        
        return jsonify({"msg": "Rule created successfully and is pending validation.", "rule": new_rule.to_dict()}), 201
        
    except yaml.YAMLError as e:
        return jsonify({"msg": f"Invalid YAML syntax: {e}"}), 400
    except ValueError as e:
        return jsonify({"msg": str(e)}), 400
    except Exception as e:
        return jsonify({"msg": f"An unexpected error occurred: {e}"}), 500


@app.route('/api/yaml', methods=['GET'])
@jwt_required()
def list_yaml_rules():
    """
    列出规则（支持分页）.
    - Admin: sees all rules.
    - Editor: sees all 'verified' rules and their own 'pending' rules.
    - User: sees only 'verified' rules.
    """
    tags_filter = request.args.get('tags')
    status_filter = request.args.get('status')  # 新增状态筛选
    search_filter = request.args.get('search')  # 新增搜索筛选
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 限制每页最大数量
    per_page = min(per_page, 1000)
    
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_user_identity).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    query = YamlRule.query

    if user.role == 'admin':
        # 管理员可以看到所有规则
        pass
    elif user.role == 'editor':
        # 编辑者可以看到所有已公开规则和自己上传的所有状态的规则
        query = query.filter(
            db.or_(
                YamlRule.status == 'published',
                YamlRule.uploaded_by == current_user_identity
            )
        )
    else:  # 'user'
        # 普通用户只能看到已公开的规则
        query = query.filter(YamlRule.status == 'published')

    # 状态筛选
    if status_filter:
        query = query.filter(YamlRule.status == status_filter)
    
    # 搜索筛选（名称或标签）- 使用子查询避免影响主查询的关联加载
    if search_filter:
        search_term = f'%{search_filter}%'
        # 使用子查询查找匹配标签的规则ID
        tag_match_subquery = db.session.query(rule_tags.c.rule_id).join(
            Tag, Tag.id == rule_tags.c.tag_id
        ).filter(Tag.name.ilike(search_term)).subquery()
        
        query = query.filter(
            db.or_(
                YamlRule.name.ilike(search_term),
                YamlRule.id.in_(tag_match_subquery)
            )
        )

    # 标签筛选 - 使用子查询避免影响主查询的关联加载
    if tags_filter:
        tag_names = tags_filter.split(',')
        tag_match_subquery = db.session.query(rule_tags.c.rule_id).join(
            Tag, Tag.id == rule_tags.c.tag_id
        ).filter(Tag.name.in_(tag_names)).subquery()
        
        query = query.filter(YamlRule.id.in_(tag_match_subquery))

    # 分页查询 - 预加载标签关系避免N+1问题
    pagination = query.options(
        db.joinedload(YamlRule.tags)
    ).order_by(YamlRule.uploaded_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'rules': [rule.to_dict() for rule in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages
    })


@app.route('/api/yaml/<int:rule_id>', methods=['PUT'])
@jwt_required()
def update_yaml_rule(rule_id):
    """
    更新规则.
    - Admin: 可以为任何规则更新 status 和 tags.
    - Editor: 只能为自己上传的 'pending' 状态的规则更新 tags.
    """
    rule = YamlRule.query.get_or_404(rule_id)
    data = request.get_json()
    
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_user_identity).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    is_admin = user.role == 'admin'
    is_owner = rule.uploaded_by == current_user_identity
    is_editor = user.role == 'editor'

    # 管理员可以编辑任何规则
    # 编辑者只能编辑自己上传的、且状态为 pending 的规则
    can_edit_tags = is_admin or (is_editor and is_owner and rule.status == 'pending')
    
    if not can_edit_tags:
        return jsonify({"msg": "Forbidden: You do not have permission to edit this rule's tags."}), 403

    if 'tags' in data:
        tags_list = data.get('tags', [])
        if not isinstance(tags_list, list):
            return jsonify({"msg": "tags must be a list of strings"}), 400
        
        rule.tags.clear()
        for tag_name in tags_list:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.session.add(tag)
            rule.tags.append(tag)

    # 只有管理员可以更新状态
    if 'status' in data and is_admin:
        new_status = data['status']
        if new_status not in ['pending', 'verified', 'published', 'failed']:
            return jsonify({"msg": "Invalid status."}), 400
        
        # 只有在规则有标签时才能将其设置为 "verified" 或 "published"
        if new_status in ['verified', 'published'] and not rule.tags:
            return jsonify({"msg": f"Cannot {new_status} a rule with no tags."}), 400

        rule.status = new_status
    
    db.session.commit()
    return jsonify({"msg": "Rule updated successfully", "rule": rule.to_dict()})


@app.route('/api/yaml/<int:rule_id>/validate', methods=['POST'])
@role_required(['admin', 'editor'])
def validate_yaml_rule(rule_id):
    """(Admin & Editor) 验证规则, 成功则状态变为 'verified', 失败则为 'failed'"""
    rule = YamlRule.query.get_or_404(rule_id)
    current_user_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_user_identity).first()

    # 权限检查: 管理员或规则所有者(编辑)
    if not (user.role == 'admin' or (user.role == 'editor' and rule.uploaded_by == current_user_identity)):
        return jsonify({"msg": "Forbidden: You can only validate your own rules."}), 403

    if rule.status not in ['pending', 'failed']:
        return jsonify({"msg": f"Rule is not in a valid state for validation (current: {rule.status})."}), 400

    if not os.path.exists(rule.file_path):
        return jsonify({"msg": "Rule file not found on server."}), 404

    nuclei_path = get_nuclei_path()
    command = [nuclei_path, '-t', rule.file_path, '-validate']
    
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        rule.status = 'verified'
        db.session.commit()
        return jsonify({
            "msg": "Validation successful. Rule status is now 'verified'.",
            "output": result.stdout.strip(),
            "rule": rule.to_dict()
        })
    except FileNotFoundError:
        return jsonify({"msg": "Error: 'nuclei' command not found. Please ensure bin/nuclei.exe exists."}), 500
    except subprocess.CalledProcessError as e:
        rule.status = 'failed'
        db.session.commit()
        return jsonify({
            "msg": "Validation failed. The rule status is now 'failed'.",
            "error": e.stderr.strip(),
            "rule": rule.to_dict()
        }), 400

@app.route('/api/yaml/<int:rule_id>/publish', methods=['POST'])
@role_required(['admin'])
def publish_yaml_rule(rule_id):
    """(Admin only) 将已验证的规则发布为公开状态"""
    rule = YamlRule.query.get_or_404(rule_id)

    if rule.status != 'verified':
        return jsonify({"msg": "Only verified rules can be published."}), 400

    rule.status = 'published'
    db.session.commit()

    return jsonify({"msg": "Rule successfully published.", "rule": rule.to_dict()})


@app.route('/api/yaml/<int:rule_id>/unpublish', methods=['POST'])
@role_required(['admin'])
def unpublish_yaml_rule(rule_id):
    """(Admin only) 取消发布规则，状态从 'published' 变回 'verified'"""
    rule = YamlRule.query.get_or_404(rule_id)

    if rule.status != 'published':
        return jsonify({"msg": "Only published rules can be unpublished."}), 400

    rule.status = 'verified'
    db.session.commit()

    return jsonify({"msg": "Rule successfully unpublished.", "rule": rule.to_dict()})


@app.route('/api/yaml/<int:rule_id>', methods=['DELETE'])
@role_required(['admin'])
def delete_yaml_rule(rule_id):
    """删除规则"""
    rule = YamlRule.query.get_or_404(rule_id)

    try:
        os.remove(rule.file_path)
    except FileNotFoundError:
        # 如果文件已不存在，我们仍然继续从数据库中删除记录
        pass
    except Exception as e:
        return jsonify({"msg": f"Error deleting file: {e}"}), 500

    db.session.delete(rule)
    db.session.commit()
    return jsonify({"msg": "Rule deleted successfully"})

# --- Tags Endpoint ---
@app.route('/api/tags', methods=['GET'])
@jwt_required()
def get_published_tags():
    """获取已发布规则的标签列表（按使用频率排序，默认返回前10个）"""
    limit = request.args.get('limit', 10, type=int)
    all_tags = request.args.get('all', 'false').lower() == 'true'
    
    # 查询已发布规则的标签，按关联规则数量排序
    from sqlalchemy import func
    query = db.session.query(
        Tag.name, 
        func.count(rule_tags.c.rule_id).label('count')
    ).join(rule_tags).join(YamlRule).filter(
        YamlRule.status == 'published'
    ).group_by(Tag.name).order_by(func.count(rule_tags.c.rule_id).desc())
    
    if not all_tags:
        query = query.limit(limit)
    
    tags = query.all()
    tag_list = [tag[0] for tag in tags]
    return jsonify(tag_list)

@app.route('/api/scan/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_scan_task(task_id):
    """删除扫描任务及其结果文件"""
    task = ScanTask.query.get_or_404(task_id)
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    # 仅管理员或任务所有者可删除
    if not (user.role == 'admin' or task.created_by == current_user):
        return jsonify({"msg": "Forbidden: You do not have permission to delete this task."}), 403

    # 删除结果文件
    if task.result_file_path and os.path.exists(task.result_file_path):
        try:
            os.remove(task.result_file_path)
        except Exception as e:
            print(f"删除结果文件 {task.result_file_path} 时出错: {e}")
            # 即使文件删除失败，也继续删除数据库记录

    db.session.delete(task)
    db.session.commit()
    return jsonify({"msg": "扫描任务已成功删除"})


# --- Scan Endpoints ---
@app.route('/api/scan/history', methods=['GET'])
@jwt_required()
def get_scan_history():
    """获取扫描任务历史（支持分页）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 限制每页最大数量
    per_page = min(per_page, 1000)
    
    current_user = get_jwt_identity()
    # 如果是 admin，可以查看所有任务
    user = User.query.filter_by(username=current_user).first()
    if user and user.role == 'admin':
        query = ScanTask.query
    else:
        query = ScanTask.query.filter_by(created_by=current_user)
    
    # 分页查询
    pagination = query.order_by(ScanTask.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'tasks': [task.to_dict() for task in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages
    })

@app.route('/api/scan', methods=['POST'])
@jwt_required()
def submit_scan():
    """提交扫描任务"""
    data = request.get_json()
    target_url = data.get('target_url')
    tags = data.get('tags')  # 期望是一个字符串列表

    if not target_url or not tags:
        return jsonify({"msg": "缺少 target_url 或 tags"}), 400

    if not isinstance(tags, list):
        return jsonify({"msg": "tags 必须是字符串列表"}), 400

    current_user = get_jwt_identity()
    tags_str = ",".join(tags)

    new_task = ScanTask(
        target_url=target_url,
        tags=tags_str,
        created_by=current_user
    )
    db.session.add(new_task)
    db.session.commit()

    # 在后台线程中运行扫描
    scan_thread = threading.Thread(target=run_scan, args=(new_task.id, app.app_context()))
    scan_thread.start()

    return jsonify({"msg": "扫描任务已成功提交", "task_id": new_task.id}), 202

@app.route('/api/scan/<int:task_id>', methods=['GET'])
@jwt_required()
def get_scan_status(task_id):
    """获取任务状态"""
    task = ScanTask.query.get_or_404(task_id)
    return jsonify(task.to_dict())

@app.route('/api/scan/<int:task_id>/summary', methods=['GET'])
@jwt_required()
def get_scan_summary(task_id):
    """获取格式化的扫描结果摘要"""
    task = ScanTask.query.get_or_404(task_id)
    
    # 基础信息
    result = {
        'id': task.id,
        'target_url': task.target_url,
        'tags': task.tags.split(',') if task.tags else [],
        'status': task.status,
        'error_log': task.error_log,
        'findings': []
    }

    if task.status != 'completed':
        return jsonify(result), 200

    if not task.result_file_path:
        return jsonify(result), 200

    summary_data = parse_nuclei_output(task.result_file_path)

    # 检查 parse_nuclei_output 是否返回了错误元组
    if isinstance(summary_data, tuple):
        # 仍然返回基础信息
        return jsonify(result), 200

    result['findings'] = summary_data.get('vulnerabilities', [])
    return jsonify(result)


@app.route('/api/scan/<int:task_id>/download', methods=['GET'])
@jwt_required()
def download_scan_result(task_id):
    """下载完整 nuclei 结果 JSON"""
    task = ScanTask.query.get_or_404(task_id)

    if not task.result_file_path or task.status != 'completed':
        return jsonify({"msg": "扫描未完成或结果文件不可用"}), 404

    try:
        return send_from_directory(
            directory=app.config['SCAN_RESULTS_FOLDER'],
            path=os.path.basename(task.result_file_path),
            as_attachment=True
        )
    except FileNotFoundError:
        return jsonify({"msg": "结果文件未找到。"}), 404


# --- 查看规则内容 ---
@app.route('/api/yaml/<int:rule_id>/content', methods=['GET'])
@jwt_required()
def get_rule_content(rule_id):
    """获取规则的 YAML 内容"""
    rule = YamlRule.query.get_or_404(rule_id)
    
    try:
        with open(rule.file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({
            'rule': rule.to_dict(),
            'content': content
        })
    except FileNotFoundError:
        return jsonify({"msg": "规则文件未找到"}), 404
    except Exception as e:
        return jsonify({"msg": f"读取文件失败: {e}"}), 500


# --- 用户管理 API ---
@app.route('/api/admin/users', methods=['GET'])
@role_required(['admin'])
def get_users():
    """获取用户列表（支持分页和搜索）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status_filter = request.args.get('status', '')
    search_filter = request.args.get('search', '')  # 新增搜索参数
    
    # 限制每页最大数量
    per_page = min(per_page, 1000)
    
    query = User.query
    
    # 状态筛选
    if status_filter:
        query = query.filter(User.status == status_filter)
    
    # 用户名模糊搜索
    if search_filter:
        query = query.filter(User.username.ilike(f'%{search_filter}%'))
    
    # 分页查询
    pagination = query.order_by(User.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'users': [user.to_dict() for user in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages
    })


@app.route('/api/admin/users/<int:user_id>/approve', methods=['POST'])
@role_required(['admin'])
def approve_user(user_id):
    """审核通过用户"""
    user = User.query.get_or_404(user_id)
    if user.status != 'pending':
        return jsonify({"msg": "只能审核待审核状态的用户"}), 400
    user.status = 'approved'
    db.session.commit()
    return jsonify({"msg": f"用户 {user.username} 已通过审核", "user": user.to_dict()})


@app.route('/api/admin/users/<int:user_id>/reject', methods=['POST'])
@role_required(['admin'])
def reject_user(user_id):
    """拒绝用户注册"""
    user = User.query.get_or_404(user_id)
    if user.status != 'pending':
        return jsonify({"msg": "只能拒绝待审核状态的用户"}), 400
    user.status = 'rejected'
    db.session.commit()
    return jsonify({"msg": f"用户 {user.username} 的注册申请已被拒绝", "user": user.to_dict()})


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@role_required(['admin'])
def delete_user(user_id):
    """删除用户"""
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        return jsonify({"msg": "不能删除默认管理员账户"}), 400
    db.session.delete(user)
    db.session.commit()
    return jsonify({"msg": f"用户 {user.username} 已删除"})


@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@role_required(['admin'])
def update_user_role(user_id):
    """修改用户角色"""
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        return jsonify({"msg": "不能修改默认管理员的角色"}), 400
    
    data = request.get_json()
    new_role = data.get('role')
    if new_role not in ['admin', 'editor', 'user']:
        return jsonify({"msg": "无效的角色"}), 400
    
    user.role = new_role
    db.session.commit()
    return jsonify({"msg": f"用户 {user.username} 的角色已更新为 {new_role}", "user": user.to_dict()})


@app.route('/api/admin/users/<int:user_id>/password', methods=['PUT'])
@role_required(['admin'])
def admin_reset_password(user_id):
    """管理员重置用户密码"""
    user = User.query.get_or_404(user_id)
    
    data = request.get_json()
    new_password = data.get('password')
    
    if not new_password or len(new_password) < 6:
        return jsonify({"msg": "密码长度至少6位"}), 400
    
    user.set_password(new_password)
    user.must_change_password = False  # 管理员重置后不强制修改
    db.session.commit()
    return jsonify({"msg": f"用户 {user.username} 的密码已重置"})


@app.route('/api/admin/users', methods=['POST'])
@role_required(['admin'])
def create_user():
    """管理员创建用户"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')
    
    if not username or not password:
        return jsonify({"msg": "请提供用户名和密码"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "用户名已存在"}), 409
    
    if role not in ['admin', 'editor', 'user']:
        return jsonify({"msg": "无效的角色"}), 400
    
    new_user = User(username=username, role=role, status='approved')
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"msg": f"用户 {username} 创建成功", "user": new_user.to_dict()}), 201


# ==================== 批量操作 API ====================

@app.route('/api/yaml/export', methods=['GET'])
@role_required(['admin', 'editor'])
def export_rules():
    """
    导出规则为压缩包
    - Admin: 可以导出所有已验证/已发布的规则
    - Editor: 只能导出自己上传的已验证/已发布的规则
    压缩包包含：YAML文件 + rules_meta.json（标签信息）
    """
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    # 查询可导出的规则（只导出 verified 和 published 状态的）
    query = YamlRule.query.filter(YamlRule.status.in_(['verified', 'published']))
    
    if user.role == 'editor':
        # 编辑者只能导出自己的规则
        query = query.filter(YamlRule.uploaded_by == current_user)
    
    rules = query.all()
    
    if not rules:
        return jsonify({"msg": "没有可导出的规则"}), 404
    
    # 构建元数据（标签和状态信息）
    rules_meta = {}
    
    # 创建内存中的 ZIP 文件
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for rule in rules:
            if os.path.exists(rule.file_path):
                # 使用规则名称作为文件名
                filename = f"{rule.name}.yaml"
                zf.write(rule.file_path, filename)
                
                # 保存状态和标签信息到元数据
                tags = [tag.name for tag in rule.tags]
                rules_meta[rule.name] = {
                    "tags": tags,
                    "status": rule.status
                }
        
        # 将元数据写入 JSON 文件
        if rules_meta:
            meta_json = json.dumps(rules_meta, ensure_ascii=False, indent=2)
            zf.writestr('rules_meta.json', meta_json.encode('utf-8'))
    
    memory_file.seek(0)
    
    # 生成文件名
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    export_filename = f"nuclens_rules_{timestamp}.zip"
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=export_filename
    )


@app.route('/api/yaml/import', methods=['POST'])
@role_required(['admin', 'editor'])
def import_rules():
    """
    批量导入规则（ZIP 压缩包）
    - Admin 和 Editor 可以导入
    - 如果压缩包包含 rules_meta.json，会自动应用标签
    - 只导入状态为 published 的规则，导入后需要重新验证
    - 已存在的规则不会覆盖，跳过
    """
    if 'file' not in request.files:
        return jsonify({"msg": "没有上传文件"}), 400
    
    file = request.files['file']
    if not file.filename.endswith('.zip'):
        return jsonify({"msg": "请上传 ZIP 格式的压缩包"}), 400
    
    current_user = get_jwt_identity()
    
    imported = []
    skipped = []
    errors = []
    rules_meta = {}  # 元数据（标签信息）
    processed_rule_ids = set()  # 跟踪本次导入已处理的规则ID，避免ZIP包内重复
    
    try:
        # 读取 ZIP 文件
        with zipfile.ZipFile(file, 'r') as zf:
            # 先检查是否有元数据文件
            if 'rules_meta.json' in zf.namelist():
                try:
                    meta_content = zf.read('rules_meta.json').decode('utf-8')
                    rules_meta = json.loads(meta_content)
                except Exception as e:
                    # 元数据解析失败不影响导入，只是没有标签
                    pass
            
            for name in zf.namelist():
                if not name.endswith(('.yaml', '.yml')):
                    continue
                
                try:
                    content = zf.read(name).decode('utf-8')
                    yaml_content = yaml.safe_load(content)
                    
                    if not isinstance(yaml_content, dict):
                        errors.append(f"{name}: 无效的 YAML 格式")
                        continue
                    
                    rule_id = yaml_content.get('id')
                    if not rule_id:
                        errors.append(f"{name}: 缺少 'id' 字段")
                        continue
                    
                    # 检查ZIP包内是否有重复（本次导入已处理过）
                    if rule_id in processed_rule_ids:
                        skipped.append(f"{name}: 规则 '{rule_id}' 在压缩包内重复，跳过")
                        continue
                    
                    # 检查元数据中的状态，只导入 published 状态的规则
                    meta_status = rules_meta.get(rule_id, {}).get('status', '')
                    if rules_meta and meta_status != 'published':
                        skipped.append(f"{name}: 规则 '{rule_id}' 状态不是 published，跳过")
                        processed_rule_ids.add(rule_id)
                        continue
                    
                    # 检查数据库中是否已存在
                    existing_rule = YamlRule.query.filter_by(name=rule_id).first()
                    if existing_rule:
                        skipped.append(f"{name}: 规则 '{rule_id}' 已存在，跳过")
                        processed_rule_ids.add(rule_id)
                        continue
                    
                    # 标记为已处理
                    processed_rule_ids.add(rule_id)
                    
                    # 保存文件
                    filename = f"{rule_id}.yaml"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    # 创建新规则
                    new_rule = YamlRule(
                        name=rule_id,
                        file_path=filepath,
                        uploaded_by=current_user,
                        status='pending'
                    )
                    db.session.add(new_rule)
                    db.session.flush()  # 获取 ID 以便添加标签
                    
                    # 应用标签（如果元数据中有）
                    if rule_id in rules_meta and 'tags' in rules_meta[rule_id]:
                        for tag_name in rules_meta[rule_id]['tags']:
                            tag = Tag.query.filter_by(name=tag_name).first()
                            if not tag:
                                tag = Tag(name=tag_name)
                                db.session.add(tag)
                                db.session.flush()
                            if tag not in new_rule.tags:
                                new_rule.tags.append(tag)
                    
                    imported.append(rule_id)
                    
                except Exception as e:
                    errors.append(f"{name}: {str(e)}")
        
        db.session.commit()
        
    except zipfile.BadZipFile:
        return jsonify({"msg": "无效的 ZIP 文件"}), 400
    
    return jsonify({
        "msg": f"导入完成：成功 {len(imported)} 个，跳过 {len(skipped)} 个，失败 {len(errors)} 个",
        "imported": imported,
        "skipped": skipped,
        "errors": errors
    })


@app.route('/api/yaml/batch/validate', methods=['POST'])
@role_required(['admin', 'editor'])
def batch_validate_rules():
    """
    批量验证规则（使用 nuclei -validate）
    - Admin: 可以验证所有规则
    - Editor: 只能验证自己上传的规则
    - 已验证/已发布的规则会跳过，不重复验证
    使用临时文件夹批量验证以提升效率
    """
    data = request.get_json()
    rule_ids = data.get('rule_ids', [])
    
    if not rule_ids:
        return jsonify({"msg": "请提供要验证的规则 ID 列表"}), 400
    
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    success = []
    failed = []
    skipped = []  # 跳过已验证/已发布的规则
    
    # 收集要验证的规则
    rules_to_validate = []
    for rule_id in rule_ids:
        rule = YamlRule.query.get(rule_id)
        if not rule:
            failed.append({"id": rule_id, "reason": "规则不存在"})
            continue
        
        # 检查权限
        if user.role != 'admin' and rule.uploaded_by != current_user:
            failed.append({"id": rule_id, "reason": "无权限验证此规则"})
            continue
        
        # 跳过已验证或已发布的规则（不需要重复验证）
        if rule.status in ['verified', 'published']:
            skipped.append({"id": rule_id, "name": rule.name, "reason": "已验证通过"})
            continue
        
        # 验证规则文件是否存在
        if not os.path.exists(rule.file_path):
            rule.status = 'failed'
            failed.append({"id": rule_id, "reason": "规则文件不存在"})
            continue
        
        rules_to_validate.append(rule)
    
    # 如果有规则需要验证，使用临时文件夹批量验证
    if rules_to_validate:
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            # 复制规则文件到临时目录
            for rule in rules_to_validate:
                shutil.copy2(rule.file_path, tmp_dir)
            
            # 使用 nuclei 批量验证临时目录
            nuclei_path = get_nuclei_path()
            command = [nuclei_path, '-t', tmp_dir, '-validate']
            try:
                result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')
                # 如果批量验证成功，所有规则设为 verified
                for rule in rules_to_validate:
                    rule.status = 'verified'
                    success.append(rule.id)
            except FileNotFoundError:
                for rule in rules_to_validate:
                    failed.append({"id": rule.id, "reason": "nuclei 命令未找到"})
            except subprocess.CalledProcessError as e:
                # 批量验证失败，解析 stderr 找出失败的规则
                error_output = e.stderr.strip()
                failed_rules = []
                
                # 解析错误输出中的文件名
                for line in error_output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    # 查找包含 .yaml 或 .yml 的行，提取文件名
                    import re
                    match = re.search(r'([^\s]+\.ya?ml)', line)
                    if match:
                        failed_filename = match.group(1)
                        # 找到对应的规则
                        for rule in rules_to_validate:
                            if os.path.basename(rule.file_path) == failed_filename:
                                failed_rules.append(rule)
                                break
                
                # 标记失败的规则
                for rule in failed_rules:
                    rule.status = 'failed'
                    failed.append({"id": rule.id, "reason": f"验证失败: {error_output[:200]}..."})
                
                # 剩余规则设为成功（假设没有错误输出的就是成功）
                for rule in rules_to_validate:
                    if rule not in failed_rules:
                        rule.status = 'verified'
                        success.append(rule.id)
    
    db.session.commit()
    
    msg_parts = [f"成功 {len(success)} 个"]
    if skipped:
        msg_parts.append(f"跳过 {len(skipped)} 个（已验证）")
    if failed:
        msg_parts.append(f"失败 {len(failed)} 个")
    
    return jsonify({
        "msg": f"批量验证完成：{'，'.join(msg_parts)}",
        "success": success,
        "skipped": skipped,
        "failed": failed
    })


@app.route('/api/yaml/batch/publish', methods=['POST'])
@role_required(['admin'])
def batch_publish_rules():
    """
    批量发布规则（仅管理员）
    只能发布 verified 状态的规则
    """
    data = request.get_json()
    rule_ids = data.get('rule_ids', [])
    
    if not rule_ids:
        return jsonify({"msg": "请提供要发布的规则 ID 列表"}), 400
    
    success = []
    failed = []
    
    for rule_id in rule_ids:
        rule = YamlRule.query.get(rule_id)
        if not rule:
            failed.append({"id": rule_id, "reason": "规则不存在"})
            continue
        
        if rule.status != 'verified':
            failed.append({"id": rule_id, "reason": f"状态为 {rule.status}，只能发布 verified 状态的规则"})
            continue
        
        rule.status = 'published'
        success.append(rule_id)
    
    db.session.commit()
    
    return jsonify({
        "msg": f"批量发布完成：成功 {len(success)} 个，失败 {len(failed)} 个",
        "success": success,
        "failed": failed
    })


@app.route('/api/yaml/batch/delete', methods=['POST'])
@role_required(['admin'])
def batch_delete_rules():
    """
    批量删除规则（仅管理员）
    """
    data = request.get_json()
    rule_ids = data.get('rule_ids', [])
    
    if not rule_ids:
        return jsonify({"msg": "请提供要删除的规则 ID 列表"}), 400
    
    success = []
    failed = []
    
    for rule_id in rule_ids:
        rule = YamlRule.query.get(rule_id)
        if not rule:
            failed.append({"id": rule_id, "reason": "规则不存在"})
            continue
        
        try:
            # 删除文件
            if os.path.exists(rule.file_path):
                os.remove(rule.file_path)
            
            # 删除数据库记录
            db.session.delete(rule)
            success.append(rule_id)
        except Exception as e:
            failed.append({"id": rule_id, "reason": str(e)})
    
    db.session.commit()
    
    return jsonify({
        "msg": f"批量删除完成：成功 {len(success)} 个，失败 {len(failed)} 个",
        "success": success,
        "failed": failed
    })


# --- System Settings Endpoints ---
@app.route('/api/settings', methods=['GET'])
@role_required(['admin'])
def get_settings():
    """获取系统设置（仅管理员）"""
    nuclei_path = SystemSettings.get('nuclei_path', DEFAULT_NUCLEI_PATH)
    nuclei_platform = SystemSettings.get('nuclei_platform', platform.system().lower())
    
    # 检查 nuclei 是否存在
    nuclei_exists = os.path.isfile(nuclei_path) if nuclei_path else False
    
    return jsonify({
        "nuclei_path": nuclei_path,
        "nuclei_platform": nuclei_platform,
        "nuclei_exists": nuclei_exists,
        "default_nuclei_path": DEFAULT_NUCLEI_PATH
    })

@app.route('/api/settings/nuclei', methods=['POST'])
@role_required(['admin'])
def upload_nuclei():
    """上传 nuclei 二进制文件（仅管理员）"""
    if 'file' not in request.files:
        return jsonify({"msg": "没有选择文件"}), 400
    
    file = request.files['file']
    platform = request.form.get('platform', 'windows')
    
    if file.filename == '':
        return jsonify({"msg": "没有选择文件"}), 400
    
    # 确定文件名
    if platform == 'windows':
        filename = 'nuclei.exe'
    else:
        filename = 'nuclei'
    
    # 确保目录存在
    if not os.path.exists(NUCLEI_BIN_FOLDER):
        os.makedirs(NUCLEI_BIN_FOLDER)
    
    # 保存文件
    filepath = os.path.join(NUCLEI_BIN_FOLDER, filename)
    file.save(filepath)
    
    # 在 Linux 上设置可执行权限
    if platform != 'windows':
        try:
            import stat
            os.chmod(filepath, os.stat(filepath).st_mode | stat.S_IEXEC)
        except:
            pass
    
    # 更新设置
    SystemSettings.set('nuclei_path', filepath)
    SystemSettings.set('nuclei_platform', platform)
    
    return jsonify({
        "msg": f"Nuclei 二进制文件已上传成功",
        "nuclei_path": filepath,
        "nuclei_platform": platform
    })

import re

def strip_ansi_codes(text):
    """清理 ANSI 颜色代码"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

@app.route('/api/settings/nuclei/test', methods=['POST'])
@role_required(['admin'])
def test_nuclei():
    """测试 nuclei 是否可用（仅管理员）"""
    nuclei_path = get_nuclei_path()
    
    if not os.path.isfile(nuclei_path):
        return jsonify({"msg": "Nuclei 文件不存在", "success": False}), 400
    
    try:
        result = subprocess.run(
            [nuclei_path, '-version'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=30
        )
        version_output = result.stdout.strip() or result.stderr.strip()
        # 清理 ANSI 颜色代码
        version_output = strip_ansi_codes(version_output)
        # 只提取版本号行
        lines = version_output.split('\n')
        version_line = next((l for l in lines if 'Version' in l), version_output.split('\n')[0] if version_output else '')
        return jsonify({
            "msg": "Nuclei 测试成功",
            "success": True,
            "version": version_line.strip()
        })
    except FileNotFoundError:
        return jsonify({"msg": "Nuclei 命令无法执行", "success": False}), 400
    except subprocess.TimeoutExpired:
        return jsonify({"msg": "Nuclei 执行超时", "success": False}), 400
    except Exception as e:
        return jsonify({"msg": f"测试失败: {str(e)}", "success": False}), 400

@app.route('/api/settings/nuclei', methods=['DELETE'])
@role_required(['admin'])
def reset_nuclei_settings():
    """重置 nuclei 设置为默认值（仅管理员）"""
    # 删除设置，回退到默认值
    setting = SystemSettings.query.filter_by(key='nuclei_path').first()
    if setting:
        db.session.delete(setting)
    setting = SystemSettings.query.filter_by(key='nuclei_platform').first()
    if setting:
        db.session.delete(setting)
    db.session.commit()
    
    return jsonify({
        "msg": "Nuclei 设置已重置为默认值",
        "nuclei_path": DEFAULT_NUCLEI_PATH
    })


@app.route('/api/settings/nuclei/update', methods=['POST'])
@role_required(['admin'])
def update_nuclei():
    """更新 nuclei 到最新版本（仅管理员）"""
    nuclei_path = get_nuclei_path()

    if not os.path.isfile(nuclei_path):
        return jsonify({"msg": "Nuclei 文件不存在", "success": False}), 400

    try:
        # 检测操作系统
        import platform
        is_windows = platform.system() == 'Windows'

        # 构建更新命令
        if is_windows:
            # Windows: nuclei.exe -update
            update_command = [nuclei_path, '-update']
        else:
            # Linux/Unix: nuclei -update
            update_command = [nuclei_path, '-update']

        # 执行更新命令
        result = subprocess.run(
            update_command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=300  # 5分钟超时
        )

        # 检查更新结果
        if result.returncode == 0:
            # 更新成功，重新获取版本信息
            version_result = subprocess.run(
                [nuclei_path, '-version'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=30
            )

            new_version = ""
            if version_result.returncode == 0:
                version_output = version_result.stdout.strip() or version_result.stderr.strip()
                version_output = strip_ansi_codes(version_output)
                lines = version_output.split('\n')
                version_line = next((l for l in lines if 'Version' in l), version_output.split('\n')[0] if version_output else '')
                new_version = version_line.strip()

            return jsonify({
                "msg": "Nuclei 更新成功",
                "success": True,
                "new_version": new_version,
                "output": result.stdout + result.stderr
            })
        else:
            return jsonify({
                "msg": "Nuclei 更新失败",
                "success": False,
                "error": result.stderr.strip() if result.stderr else result.stdout.strip()
            }), 400

    except subprocess.TimeoutExpired:
        return jsonify({"msg": "Nuclei 更新超时（5分钟）", "success": False}), 400
    except FileNotFoundError:
        return jsonify({"msg": "Nuclei 命令无法执行", "success": False}), 400
    except Exception as e:
        return jsonify({"msg": f"更新失败: {str(e)}", "success": False}), 400


# --- SSL/HTTPS 证书管理 ---
CERTS_FOLDER = os.path.join(basedir, 'certs')

@app.route('/api/settings/ssl', methods=['GET'])
@role_required(['admin'])
def get_ssl_settings():
    """获取 SSL/HTTPS 配置状态（仅管理员）"""
    # 从配置文件读取
    try:
        import config
        https_enabled = getattr(config, 'HTTPS_ENABLED', False)
        cert_path = getattr(config, 'SSL_CERT_PATH', 'certs/cert.pem')
        key_path = getattr(config, 'SSL_KEY_PATH', 'certs/key.pem')
    except ImportError:
        https_enabled = False
        cert_path = 'certs/cert.pem'
        key_path = 'certs/key.pem'
    
    # 检查证书文件是否存在
    abs_cert_path = cert_path if os.path.isabs(cert_path) else os.path.join(basedir, cert_path)
    abs_key_path = key_path if os.path.isabs(key_path) else os.path.join(basedir, key_path)
    
    cert_exists = os.path.isfile(abs_cert_path)
    key_exists = os.path.isfile(abs_key_path)
    
    # 获取证书信息
    cert_info = None
    if cert_exists:
        try:
            import ssl
            import datetime
            # 读取证书信息
            with open(abs_cert_path, 'r') as f:
                cert_content = f.read()
            # 使用 OpenSSL 解析证书（如果可用）
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                cert = x509.load_pem_x509_certificate(cert_content.encode(), default_backend())
                cert_info = {
                    'subject': cert.subject.rfc4514_string(),
                    'issuer': cert.issuer.rfc4514_string(),
                    'not_before': cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat(),
                    'not_after': cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat(),
                    'serial_number': str(cert.serial_number)
                }
            except ImportError:
                # cryptography 库不可用，只返回基本信息
                cert_info = {'note': '安装 cryptography 库可查看详细证书信息'}
        except Exception as e:
            cert_info = {'error': str(e)}
    
    return jsonify({
        "https_enabled": https_enabled,
        "cert_path": cert_path,
        "key_path": key_path,
        "cert_exists": cert_exists,
        "key_exists": key_exists,
        "cert_info": cert_info
    })


@app.route('/api/settings/ssl/toggle', methods=['POST'])
@role_required(['admin'])
def toggle_https():
    """切换 HTTPS 状态（仅管理员）"""
    data = request.get_json() or {}
    enabled = data.get('enabled', False)
    
    # 检查证书是否存在
    cert_path = os.path.join(CERTS_FOLDER, 'cert.pem')
    key_path = os.path.join(CERTS_FOLDER, 'key.pem')
    
    if enabled and (not os.path.exists(cert_path) or not os.path.exists(key_path)):
        return jsonify({"msg": "请先上传或生成 SSL 证书"}), 400
    
    # 读取并修改 config.py
    config_path = os.path.join(basedir, 'config.py')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_content = f.read()
        
        # 替换 HTTPS_ENABLED 的值
        import re
        new_value = 'True' if enabled else 'False'
        
        if 'HTTPS_ENABLED' in config_content:
            config_content = re.sub(
                r'HTTPS_ENABLED\s*=\s*(True|False)',
                f'HTTPS_ENABLED = {new_value}',
                config_content
            )
        else:
            # 如果配置项不存在，添加到文件末尾
            config_content += f'\n\n# HTTPS 配置\nHTTPS_ENABLED = {new_value}\n'
        
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(config_content)
        
        # 重新加载配置模块
        import importlib
        import config
        importlib.reload(config)
        
        status_text = '启用' if enabled else '关闭'
        return jsonify({
            "msg": f"HTTPS 已{status_text}，请重启服务使配置生效",
            "https_enabled": enabled,
            "need_restart": True
        })
        
    except Exception as e:
        return jsonify({"msg": f"修改配置失败: {str(e)}"}), 500


@app.route('/api/settings/ssl/upload', methods=['POST'])
@role_required(['admin'])
def upload_ssl_certificate():
    """上传 SSL 证书和私钥（仅管理员）"""
    if 'cert' not in request.files or 'key' not in request.files:
        return jsonify({"msg": "请同时上传证书文件(cert)和私钥文件(key)"}), 400
    
    cert_file = request.files['cert']
    key_file = request.files['key']
    
    if cert_file.filename == '' or key_file.filename == '':
        return jsonify({"msg": "请选择证书和私钥文件"}), 400
    
    # 确保目录存在
    if not os.path.exists(CERTS_FOLDER):
        os.makedirs(CERTS_FOLDER)
    
    cert_path = os.path.join(CERTS_FOLDER, 'cert.pem')
    key_path = os.path.join(CERTS_FOLDER, 'key.pem')
    
    try:
        # 保存文件
        cert_file.save(cert_path)
        key_file.save(key_path)
        
        # 验证证书和私钥是否匹配
        try:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
        except ssl.SSLError as e:
            # 删除无效的证书文件
            if os.path.exists(cert_path):
                os.remove(cert_path)
            if os.path.exists(key_path):
                os.remove(key_path)
            return jsonify({"msg": f"证书验证失败: {str(e)}"}), 400
        
        return jsonify({
            "msg": "SSL 证书上传成功！请在 config.py 中设置 HTTPS_ENABLED = True 并重启服务",
            "cert_path": "certs/cert.pem",
            "key_path": "certs/key.pem"
        })
        
    except Exception as e:
        return jsonify({"msg": f"上传失败: {str(e)}"}), 500


@app.route('/api/settings/ssl/generate', methods=['POST'])
@role_required(['admin'])
def generate_self_signed_cert():
    """生成自签名证书（仅管理员）"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
        
        data = request.get_json() or {}
        common_name = data.get('common_name', 'localhost')
        days_valid = data.get('days_valid', 365)
        
        # 生成私钥
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 生成证书
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NucLens"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(common_name),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())
        
        # 确保目录存在
        if not os.path.exists(CERTS_FOLDER):
            os.makedirs(CERTS_FOLDER)
        
        # 保存证书
        cert_path = os.path.join(CERTS_FOLDER, 'cert.pem')
        key_path = os.path.join(CERTS_FOLDER, 'key.pem')
        
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        return jsonify({
            "msg": f"自签名证书生成成功！有效期 {days_valid} 天。请在 config.py 中设置 HTTPS_ENABLED = True 并重启服务",
            "cert_path": "certs/cert.pem",
            "key_path": "certs/key.pem",
            "common_name": common_name,
            "days_valid": days_valid
        })
        
    except ImportError:
        return jsonify({"msg": "请先安装 cryptography 库: pip install cryptography"}), 400
    except Exception as e:
        return jsonify({"msg": f"生成证书失败: {str(e)}"}), 500


@app.route('/api/settings/ssl/delete', methods=['DELETE'])
@role_required(['admin'])
def delete_ssl_certificate():
    """删除 SSL 证书（仅管理员）"""
    cert_path = os.path.join(CERTS_FOLDER, 'cert.pem')
    key_path = os.path.join(CERTS_FOLDER, 'key.pem')
    
    deleted = []
    if os.path.exists(cert_path):
        os.remove(cert_path)
        deleted.append('cert.pem')
    if os.path.exists(key_path):
        os.remove(key_path)
        deleted.append('key.pem')
    
    if deleted:
        return jsonify({"msg": f"已删除: {', '.join(deleted)}"})
    else:
        return jsonify({"msg": "没有找到证书文件"})


@app.route('/api/settings/restart', methods=['POST'])
@role_required(['admin'])
def restart_service():
    """重启服务提示（仅管理员）"""
    # 检测运行环境
    in_docker = os.path.exists('/.dockerenv')
    
    if in_docker:
        return jsonify({
            "msg": "请在宿主机执行命令重启容器",
            "success": False,
            "command": "docker restart nuclens"
        })
    else:
        # 本地开发环境：提示用户手动重启
        return jsonify({
            "msg": "请手动重启服务（Ctrl+C 后重新运行 python app.py）",
            "success": False,
            "command": "python app.py"
        })


if __name__ == '__main__':
    import ipaddress  # 用于生成自签名证书
    
    with app.app_context():
        db.create_all()
        # 创建默认管理员账户
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                role='admin',
                status='approved',
                must_change_password=True
            )
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print("默认管理员账户已创建: admin / admin")
    
    # 读取配置
    try:
        import config
        https_enabled = getattr(config, 'HTTPS_ENABLED', False)
        ssl_cert = getattr(config, 'SSL_CERT_PATH', 'certs/cert.pem')
        ssl_key = getattr(config, 'SSL_KEY_PATH', 'certs/key.pem')
        app_port = getattr(config, 'APP_PORT', 5001)
        debug_mode = getattr(config, 'DEBUG_MODE', False)
    except ImportError:
        https_enabled = False
        ssl_cert = 'certs/cert.pem'
        ssl_key = 'certs/key.pem'
        app_port = 5001
        debug_mode = False
    
    # 环境变量覆盖
    if os.environ.get('FLASK_ENV') == 'production':
        debug_mode = False
    
    # 启动服务
    if https_enabled:
        # 转换为绝对路径
        abs_cert = ssl_cert if os.path.isabs(ssl_cert) else os.path.join(basedir, ssl_cert)
        abs_key = ssl_key if os.path.isabs(ssl_key) else os.path.join(basedir, ssl_key)
        
        if os.path.exists(abs_cert) and os.path.exists(abs_key):
            print(f"🔒 HTTPS 模式启动，端口: {app_port}")
            app.run(host='0.0.0.0', port=app_port, debug=debug_mode, ssl_context=(abs_cert, abs_key))
        else:
            print(f"⚠️ 证书文件不存在，回退到 HTTP 模式")
            print(f"   证书路径: {abs_cert}")
            print(f"   私钥路径: {abs_key}")
            app.run(host='0.0.0.0', port=app_port, debug=debug_mode)
    else:
        print(f"🌐 HTTP 模式启动，端口: {app_port}")
        app.run(host='0.0.0.0', port=app_port, debug=debug_mode)
