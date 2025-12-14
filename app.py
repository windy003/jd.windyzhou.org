from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
from datetime import timedelta
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

app = Flask(__name__)
# 从环境变量读取 secret_key，如果不存在则使用随机生成的（仅用于开发）
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
CORS(app)

# ========== 配置区域（从环境变量读取，保护敏感信息） ==========
# 账号密码（使用哈希加密存储）
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', )
admin_password = os.getenv('ADMIN_PASSWORD', )  # 默认仅用于开发
ADMIN_PASSWORD_HASH = generate_password_hash(admin_password)

# 站长联系方式
ADMIN_CONTACT = os.getenv('ADMIN_CONTACT', "周秋良:手机:15868404601,微信同号")
# ========================================================

# 数据文件路径
DATA_FILE = 'posts.json'

def load_posts():
    """从文件加载信息数据"""
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

def save_posts(posts):
    """保存信息数据到文件"""
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(posts, f, ensure_ascii=False, indent=2)

# 路由：前台页面
@app.route('/')
def index():
    return render_template('index.html', admin_contact=ADMIN_CONTACT)

# 路由：后台登录页面
@app.route('/admin')
def admin():
    return render_template('admin.html')

# API：获取所有信息
@app.route('/api/posts', methods=['GET'])
def get_posts():
    posts = load_posts()
    category = request.args.get('category', '全部')

    if category != '全部':
        posts = [p for p in posts if p.get('category') == category]

    return jsonify({'success': True, 'data': posts})

# API：站长登录
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
        session['admin_logged_in'] = True
        session.permanent = True
        return jsonify({'success': True, 'message': '登录成功'})
    else:
        return jsonify({'success': False, 'message': '账号或密码错误'})

# API：检查登录状态
@app.route('/api/check_login', methods=['GET'])
def check_login():
    is_logged_in = session.get('admin_logged_in', False)
    return jsonify({'success': True, 'logged_in': is_logged_in})

# API：退出登录
@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('admin_logged_in', None)
    return jsonify({'success': True, 'message': '已退出登录'})

# API：发布信息（需要登录）
@app.route('/api/posts', methods=['POST'])
def create_post():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': '未登录'}), 401

    data = request.get_json()
    posts = load_posts()

    new_post = {
        'id': len(posts) + 1,
        'category': data.get('category'),
        'title': data.get('title'),
        'content': data.get('content'),
        'contact': data.get('contact'),
        'timestamp': data.get('timestamp')
    }

    posts.append(new_post)
    save_posts(posts)

    return jsonify({'success': True, 'message': '发布成功', 'data': new_post})

# API：删除信息（需要登录）
@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': '未登录'}), 401

    posts = load_posts()
    posts = [p for p in posts if p.get('id') != post_id]
    save_posts(posts)

    return jsonify({'success': True, 'message': '删除成功'})

if __name__ == '__main__':
    # 创建 templates 目录
    os.makedirs('templates', exist_ok=True)

    # 运行应用
    print("=" * 50)
    print("服务器启动成功！")
    print("前台页面: http://127.0.0.1:5000/")
    print("后台管理: http://127.0.0.1:5000/admin")
    print("默认账号: admin")
    print("默认密码: 123456")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5002)
