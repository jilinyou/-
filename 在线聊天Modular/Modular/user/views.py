import os

from flask import render_template, session, jsonify
from flask import request, redirect, url_for, flash
from flask_socketio import send, emit, join_room, leave_room

from extensions import db
from extensions import socketio
from utils.decorators import login_required  # 导入权限检查装饰器
from werkzeug.utils import secure_filename, send_from_directory

# 修改导入为绝对导入
from user import user_bp
from user.models import User, ActivationCode, Message, ChatRequest

# 文件上传的配置
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# 用户登录功能
@user_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 查询数据库中的用户信息
        user = User.query.filter_by(username=username, password=password).first()

        if user:
            # 检查用户账号状态
            if not user.is_active:
                flash('您的账号已被封禁，请联系管理员！', 'danger')
                return redirect(url_for('user.login'))

            # 登录成功，将用户信息存储到 session 中
            session['user_id'] = user.id
            session['username'] = user.username  # 存储用户名

            # 根据用户角色跳转到对应的页面
            if user.is_admin:
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('user.dashboard'))

        # 登录失败，显示错误提示
        flash('用户名或密码错误', 'danger')
        return redirect(url_for('user.login'))

    # 渲染登录页面
    return render_template('login.html')


# 用户注销功能
@user_bp.route('/logout')
@login_required
def logout():
    """用户注销功能"""
    session.pop('user_id', None)  # 清除用户会话
    flash('您已成功注销！', 'success')
    return redirect(url_for('user.login'))


# 用户注册功能
@user_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        id_card = request.form['id_card']
        phone_number = request.form['phone_number']
        wechat_qq = request.form['wechat_qq']
        address = request.form['address']
        activation_code = request.form['activation_code']

        # 验证激活码是否有效
        code = ActivationCode.query.filter_by(code=activation_code).first()
        if not code:
            flash('激活码无效，请检查输入是否正确。', 'danger')
        elif code.is_used:
            flash('激活码已被使用，请联系管理员获取新的激活码。', 'warning')
        else:
            # 激活码有效，创建新用户
            new_user = User(
                username=username,
                password=password,
                id_card=id_card,
                phone_number=phone_number,
                wechat_qq=wechat_qq,
                address=address,
                is_admin=False,
                activation_code_id=code.id
            )
            db.session.add(new_user)
            # 标记激活码为已使用
            code.is_used = True
            db.session.commit()

            flash('注册成功！', 'success')
            return redirect(url_for('user.login'))

    return render_template('register.html')


# 用户仪表盘
@user_bp.route('/dashboard')
@login_required
def dashboard():
    """用户仪表盘"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        flash('用户不存在，请重新登录！', 'danger')
        return redirect(url_for('user.login'))

    # 渲染仪表盘页面，传递用户数据
    return render_template('user/dashboard.html', user=user)


# 用户扣钱的后端
@user_bp.route('/use_service', methods=['POST'])
@login_required
def use_service():
    """用户调用服务，扣除虚拟币"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if not user:
        flash('用户未登录，请先登录！', 'danger')
        return redirect(url_for('user.login'))

    if not user.is_active:
        flash('您的账号已被封禁，无法使用服务！', 'danger')
        return redirect(url_for('user.dashboard'))

    # 检查余额是否足够
    service_cost = 10.0  # 假设服务消耗10虚拟币
    if user.virtual_money < service_cost:
        flash('余额不足，无法调用该服务！', 'danger')
        return redirect(url_for('user.dashboard'))

    # 扣除虚拟币
    user.virtual_money -= service_cost
    db.session.commit()
    flash(f'服务调用成功！已扣除 {service_cost} 虚拟币，当前余额：{user.virtual_money}', 'success')
    return redirect(url_for('user.dashboard'))


# 用户个人信息页面
@user_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """普通用户查询和修改信息页面"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if not user:
        flash('用户不存在，请重新登录！', 'danger')
        return redirect(url_for('user.login'))

    if request.method == 'POST':
        # 获取表单数据并更新用户信息（不包括虚拟币余额）
        user.username = request.form['username']
        user.password = request.form['password']
        user.id_card = request.form['id_card']
        user.phone_number = request.form['phone_number']
        user.wechat_qq = request.form['wechat_qq']
        user.address = request.form['address']

        db.session.commit()
        flash('信息已更新！', 'success')
        return redirect(url_for('user.profile'))

    # 渲染用户信息页面
    return render_template('user/profile.html', user=user)

@user_bp.route('/messages')
@login_required
def view_messages():
    user_id = session.get('user_id')

    # 获取用户的消息
    messages = Message.query.filter((Message.receiver_id == user_id)).all()

    return render_template('user/messages.html', messages=messages)

@user_bp.route('/send_chat_request', methods=['POST'])
@login_required
def send_chat_request():
    data = request.get_json()
    target_user_id = data.get('target_user_id')

    if not target_user_id:
        return jsonify({'error': '目标用户 ID 缺失'}), 400

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': '用户未登录'}), 401

    # 检查目标用户是否存在
    target_user = User.query.get(target_user_id)
    if not target_user:
        return jsonify({'error': '目标用户不存在'}), 404

    # 创建聊天请求
    chat_request = ChatRequest(user_id=user_id, admin_id=target_user_id)
    db.session.add(chat_request)
    db.session.commit()

    return jsonify({'success': True}), 200


@user_bp.route('/chat')
@login_required
def chat():
    """用户聊天页面"""
    user_id = session.get('user_id')  # 从 session 获取当前用户的 ID
    user = User.query.get(user_id)  # 查询数据库中的用户信息
    if not user:
        flash('用户不存在，请重新登录！', 'danger')
        return redirect(url_for('user.login'))

    return render_template('user/chat.html', user=user)

@socketio.on('message')
def handle_message(message):
    """处理接收到的消息"""
    print(f"Received message: {message}")
    send(message, broadcast=True)  # 广播给所有连接的客户端

@socketio.on('private_message')
def handle_private_message(data):
    """处理私聊消息"""
    receiver_id = data['receiver_id']
    message = data['message']
    emit('private_message', message, room=receiver_id)  # 将消息发送给接收者


# 用户加入聊天室
@socketio.on('join')
def on_join(data):
    """处理用户加入聊天室事件"""
    username = data.get('username')  # 安全获取 'username' 字段
    room = data.get('room', 'main_room')  # 获取房间名称，默认为 'main_room'

    if not username:  # 如果用户名不存在，返回错误消息
        emit('error', {'message': '用户名不能为空！'})
        return

    # 将用户加入房间
    join_room(room)
    emit('message', {'username': '系统', 'message': f'{username} 已加入聊天室'}, to=room)


# 处理用户离开聊天室
@socketio.on('leave')
def on_leave(data):
    """用户离开聊天室"""
    username = session.get('username')  # 从 session 获取用户名
    room = data.get('room', 'main_room')  # 默认房间
    leave_room(room)
    emit('message', {'username': '系统', 'message': f'{username} 已离开聊天室'}, to=room)

# 处理消息发送
@socketio.on('send_message')
def handle_send_message(data):
    """用户发送消息"""
    # 从会话中获取用户名
    username = session.get('username')  # 确保用户已登录
    if not username:
        emit('error', {'message': '用户未登录，请重新登录后再试！'})
        return

    room = data.get('room', 'main_room')  # 获取房间，默认为主房间
    message = data.get('message')  # 获取消息内容

    if not message.strip():  # 验证消息内容是否为空
        emit('error', {'message': '消息内容不能为空！'})
        return

    # 广播消息到房间
    emit('message', {'username': username, 'message': message}, to=room)

    # 可选：记录消息到数据库（如果需要）
    # chat_message = ChatMessage(username=username, room=room, message=message)
    # db.session.add(chat_message)
    # db.session.commit()

@user_bp.route('/chat_request')
@login_required
def chat_request():
    """用户聊天请求页面"""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        flash('用户不存在，请重新登录！', 'danger')
        return redirect(url_for('user.login'))

    users = User.query.all()  # 获取所有用户列表
    return render_template('user/chat_request.html', user=user, users=users)

@user_bp.route('/chat_targets', methods=['GET'])
@login_required
def chat_targets():
    """获取当前用户可以聊天的目标列表"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': '用户未登录'}), 403

    # 获取所有接受的聊天请求（目标为当前用户或管理员接受了用户的请求）
    accepted_requests = ChatRequest.query.filter(
        (ChatRequest.user_id == user_id) & (ChatRequest.status == 'accepted')
    ).all()

    targets = [{'id': req.admin_id, 'username': req.admin.username} for req in accepted_requests]
    return jsonify({'targets': targets})
# 确保上传目录存在
# 确保上传目录存在
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@user_bp.route('/upload', methods=['POST'])
def upload_file():
    """处理文件上传"""
    if 'file' not in request.files:
        return jsonify({'error': '未选择文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '文件名不能为空'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': '文件类型不允许'}), 400

    filename = secure_filename(file.filename)  # 确保文件名安全
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)  # 保存文件

    # 添加调试日志
    print(f"文件成功保存到: {file_path}")

    return jsonify({'file_url': f'/uploads/{filename}'}), 200

@user_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    """提供上传文件的访问"""
    return send_from_directory(UPLOAD_FOLDER, filename)

@socketio.on('send_file')
def handle_send_file(data):
    """广播文件到房间"""
    username = session.get('user.id')  # 获取当前用户名
    room = data.get('room', 'main_room')  # 获取房间
    file_url = data.get('file_url')  # 文件的 URL

    if not username or not file_url:
        emit('error', {'message': '用户名或文件路径不能为空！'})
        return

    # 广播文件信息到房间
    emit('file_message', {'username': username, 'file_url': file_url}, to=room)