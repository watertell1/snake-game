import os
import re
from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime,timedelta
from flask import send_from_directory
from flask import g


app = Flask(__name__)

# 数据库配置（请根据你的MySQL信息修改）
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Yhr20050420.@localhost/game_db'
app.config['SECRET_KEY'] = 'your-secret-key-123'  # 必须设置，用于会话加密
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # 开发环境关闭HTTPS验证
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CORS配置（允许前端跨域请求）
CORS(app, supports_credentials=True, origins=['http://localhost:5000', 'http://127.0.0.1:5000'])

db = SQLAlchemy(app)


# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(50), unique=True, nullable=False)  # 登录账号
    username = db.Column(db.String(50), unique=True, nullable=False)  # 显示名称
    password = db.Column(db.String(128), nullable=False)  # 密码（实际项目需加密）


class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    moves = db.Column(db.Integer, nullable=False)
    time = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# 存储权限配置
class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)

with app.app_context():
    db.create_all()

# 注册接口
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    account = data.get('account')
    username = data.get('username')
    password = data.get('password')

    if not all([account, username, password]):
        return jsonify({"error": "账号、用户名和密码不能为空"}), 400

    if User.query.filter_by(account=account).first():
        return jsonify({"error": "账号已存在"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "用户名已存在"}), 400

    try:
        new_user = User(account=account, username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "注册成功，请登录"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"注册失败：{str(e)}"}), 500


# 登录接口
@app.route('/api/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"error": "请求必须是JSON格式"}), 415

    data = request.json
    account = data.get('account')
    password = data.get('password')

    if not all([account, password]):
        return jsonify({"error": "账号和密码不能为空"}), 400

    try:
        user = User.query.filter_by(account=account).first()
        if not user or user.password != password:
            return jsonify({"error": "账号或密码错误"}), 401

        # 重置会话，防止固定攻击
        session.clear()
        session['user_id'] = user.id
        # 标记管理员（账号为admin1的用户）
        session['is_admin'] = (account == 'admin1')

        # 管理员登录返回管理员页面地址，普通用户返回首页
        response = {
            "message": "登录成功",
            "user": {"id": user.id, "username": user.username}
        }
        if session['is_admin']:
            response["redirect"] = "/admin.html"
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": f"登录失败：{str(e)}"}), 500


# 静态文件访问（前端页面）
@app.route('/<path:path>')
def serve_static(path):
    response = send_from_directory(os.path.join(app.root_path, 'templates'), path)
    # 对管理员页面添加禁止缓存的响应头
    if path == 'admin.html':
        # 禁止缓存策略：不缓存，每次都从服务器获取
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'  # 兼容HTTP/1.0
        response.headers['Expires'] = '0'  # 立即过期
    return response


# 首页重定向
@app.route('/')
def index():
    return redirect(url_for('serve_static', path='index.html'))


# 检查登录状态
@app.route('/api/check_login', methods=['GET'])
def check_login():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"message": "未登录"}), 200
    user = User.query.get(user_id)
    return jsonify({
        "message": "已登录",
        "username": user.username,
        "is_admin": session.get('is_admin', False)  # 返回是否为管理员
    }), 200


# 保存游戏记录
@app.route('/api/game', methods=['POST'])
def save_game():
    if 'user_id' not in session:
        return jsonify({"error": "未登录"}), 401

    data = request.json
    score = data.get('score')
    moves = data.get('moves')
    time = data.get('time')

    if not isinstance(score, int) or not isinstance(moves, int) or not time:
        return jsonify({"error": "无效的游戏数据"}), 400

    try:
        new_history = History(
            user_id=session['user_id'],
            score=score,
            moves=moves,
            time=time
        )
        db.session.add(new_history)
        db.session.commit()
        return jsonify({"message": "记录已保存"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"保存失败：{str(e)}"}), 500


# 排行榜接口
from sqlalchemy import func, over
@app.route('/api/ranking', methods=['GET'])
def ranking():
    try:
        # 子查询：获取每个用户的最高分
        subquery = db.session.query(
            History.user_id,
            func.max(History.score).label('max_score')
        ).group_by(History.user_id).subquery()

        # 主查询：查找用户和对应的最高分记录
        records = db.session.query(
            User.username,
            History.score,
            History.moves,
            History.time,
            History.created_at
        ).join(History, User.id == History.user_id)\
         .join(subquery, (History.user_id == subquery.c.user_id) & (History.score == subquery.c.max_score))\
         .order_by(History.score.desc())\
         .limit(10)\
         .all()

        result = [{
            "username": r.username,
            "score": r.score,
            "moves": r.moves,
            "time": r.time,
            "created_at": r.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for r in records]

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"获取排行榜失败：{str(e)}"}), 500



# 退出登录
@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "已退出登录"})


# 用户历史记录
@app.route('/api/history', methods=['GET'])
def get_history():
    if 'user_id' not in session:
        return jsonify({"error": "未登录"}), 401

    try:
        records = History.query.filter_by(
            user_id=session['user_id']
        ).order_by(History.created_at.desc()).all()
        return jsonify([{
            "created_at": r.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "score": r.score,
            "moves": r.moves,
            "time": r.time
        } for r in records])
    except Exception as e:
        return jsonify({"error": f"获取记录失败：{str(e)}"}), 500


# 重置密码
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    account = data.get('account')
    username = data.get('username')
    new_password = data.get('newPassword')

    if not all([account, username, new_password]):
        return jsonify({"error": "账号、用户名和新密码不能为空"}), 400

    try:
        user = User.query.filter_by(account=account, username=username).first()
        if not user:
            return jsonify({"error": "账号或用户名不正确"}), 404

        # 简单密码验证（至少6位，包含字母和数字）
        import re
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d).{6,}$', new_password):
            return jsonify({"error": "密码需至少6位，包含字母和数字"}), 400

        user.password = new_password
        db.session.commit()
        return jsonify({"message": "密码重置成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"重置失败：{str(e)}"}), 500


# 中间件：检查登录和管理员权限
@app.before_request
def check_permission():
    path = request.path
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', False)
    current_role = 'admin' if is_admin else ('user' if user_id else 'common')

    # 匹配数据库中是否存在该路径+角色
    from sqlalchemy import or_
    allowed = False

    # 支持动态 URL 匹配
    permission_entries = Permission.query.all()
    for perm in permission_entries:
        pattern = '^' + re.sub(r'<[^>]+>', r'[^/]+', perm.url) + '$'
        if re.match(pattern, path) and perm.role == current_role:
            allowed = True
            break
        # 允许 admin 拥有 user 和 common 权限
        elif is_admin and perm.role in ['user', 'common'] and re.match(pattern, path):
            allowed = True
            break
        # 允许 user 拥有 common 权限
        elif current_role == 'user' and perm.role == 'common' and re.match(pattern, path):
            allowed = True
            break

    if not allowed:
        return redirect('/login.html')

@app.after_request
def disable_cache_for_html(response):
    if request.path.endswith('.html'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


# 管理员接口：获取所有用户
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    if not session.get('is_admin'):
        return jsonify({"error": "无权限"}), 403
    try:
        users = User.query.all()
        return jsonify([{
            "id": u.id,
            "account": u.account,
            "username": u.username
        } for u in users])
    except Exception as e:
        return jsonify({"error": f"获取失败：{str(e)}"}), 500


# 管理员接口：删除用户
@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    if not session.get('is_admin'):
        return jsonify({"error": "无权限"}), 403
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "用户不存在"}), 404
        # 同时删除用户的游戏记录
        History.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "删除成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"删除失败：{str(e)}"}), 500


# 管理员接口：更新用户
@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
def admin_update_user(user_id):
    if not session.get('is_admin'):
        return jsonify({"error": "无权限"}), 403
    data = request.json
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "用户不存在"}), 404
        if 'account' in data:
            user.account = data['account']
        if 'username' in data:
            user.username = data['username']
        if 'password' in data:
            user.password = data['password']
        db.session.commit()
        return jsonify({"message": "更新成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"更新失败：{str(e)}"}), 500


# 管理员接口：获取用户游戏记录
@app.route('/api/admin/users/<int:user_id>/history', methods=['GET'])
def admin_get_user_history(user_id):
    if not session.get('is_admin'):
        return jsonify({"error": "无权限"}), 403
    try:
        records = History.query.filter_by(user_id=user_id
                                          ).order_by(History.created_at.desc()).all()
        return jsonify([{
            "created_at": r.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "score": r.score,
            "moves": r.moves,
            "time": r.time
        } for r in records])
    except Exception as e:
        return jsonify({"error": f"获取失败：{str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)