import os

from flask import render_template, request, redirect, url_for, flash, session
from extensions import db
from extensions import socketio
from user.models import User, ActivationCode, Message, ChatRequest  # 修改为绝对导入
from utils.decorators import admin_required  # 引入管理员权限验证装饰器
from user.views import UPLOAD_FOLDER  # 修改为绝对导入
from . import admin_bp  # 保留相对导入，表示当前模块的蓝图

from flask_socketio import send, emit, join_room, leave_room  # WebSocket 相关


# 管理员后台主页
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    return render_template('admin/dashboard.html')

# 管理用户页面
@admin_bp.route('/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    # 处理搜索
    search_query = request.args.get('search_query', '').strip()

    # 获取普通用户
    query = User.query.filter_by(is_admin=False)
    if search_query:
        query = query.filter(
            db.or_(
                User.username.ilike(f"%{search_query}%"),
                User.phone_number.ilike(f"%{search_query}%")
            )
        )
    users = query.all()

    # 处理批量删除
    if request.method == 'POST':
        selected_ids = request.form.getlist('selected_ids')  # 获取选中的用户ID列表
        if selected_ids:
            User.query.filter(User.id.in_(selected_ids)).delete(synchronize_session=False)
            db.session.commit()
            flash(f'成功删除 {len(selected_ids)} 个用户！', 'success')
        else:
            flash('请选择要删除的用户', 'warning')
        return redirect(url_for('admin.manage_users'))

    return render_template('admin/manage_users.html', users=users, search_query=search_query)

# 注销路由
@admin_bp.route('/logout')
@admin_required
def logout():
    # 清除 session 中的用户信息
    session.pop('user_id', None)
    flash('您已成功注销！', 'success')
    return redirect(url_for('user.login'))

# 管理员修改密码页面
@admin_bp.route('/change_password', methods=['GET', 'POST'])
@admin_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # 获取当前管理员用户
        admin_user = User.query.filter_by(id=session.get('user_id'), is_admin=True).first()

        if not admin_user:
            flash('未找到管理员账户，请重新登录！', 'danger')
            return redirect(url_for('user.login'))

        # 验证当前密码
        if admin_user.password != current_password:
            flash('当前密码不正确，请重试！', 'danger')
            return redirect(url_for('admin.change_password'))

        # 验证新密码一致性
        if new_password != confirm_password:
            flash('新密码和确认密码不一致，请重试！', 'danger')
            return redirect(url_for('admin.change_password'))

        # 更新密码
        admin_user.password = new_password
        db.session.commit()
        flash('密码修改成功！', 'success')
        return redirect(url_for('admin.dashboard'))

    return render_template('admin/change_password.html')

# 编辑用户页面
@admin_bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        # 更新用户信息
        user.username = request.form['username']
        user.phone_number = request.form['phone_number']
        user.wechat_qq = request.form['wechat_qq']
        user.address = request.form['address']
        user.password = request.form['password']
        db.session.commit()
        flash('用户信息已更新！', 'success')
        return redirect(url_for('admin.manage_users'))
    return render_template('admin/edit_user.html', user=user)

# 管理激活码页面（支持搜索、筛选、批量添加和删除）
@admin_bp.route('/manage_activation_codes', methods=['GET', 'POST'])
@admin_required
def manage_activation_codes():
    # 搜索和筛选参数
    search_user = request.args.get('search_user', '')  # 搜索使用者用户名
    filter_status = request.args.get('filter_status', '')  # 筛选激活码状态

    # 处理批量删除
    if request.method == 'POST':
        if 'delete_selected' in request.form:
            selected_ids = request.form.getlist('selected_ids')  # 获取勾选的激活码ID
            ActivationCode.query.filter(ActivationCode.id.in_(selected_ids)).delete(synchronize_session=False)
            db.session.commit()
            flash('选中的激活码已删除！', 'success')
            return redirect(url_for('admin.manage_activation_codes'))
        # 批量添加激活码
        elif 'add_activation_codes' in request.form:
            activation_codes = request.form['activation_codes']
            codes = activation_codes.splitlines()  # 逐行分割激活码
            for code in codes:
                if code.strip():  # 忽略空行
                    existing_code = ActivationCode.query.filter_by(code=code.strip()).first()
                    if not existing_code:
                        new_code = ActivationCode(code=code.strip(), is_used=False)
                        db.session.add(new_code)
            db.session.commit()
            flash('激活码批量添加成功！', 'success')
            return redirect(url_for('admin.manage_activation_codes'))

    # 查询激活码，应用搜索和筛选
    query = ActivationCode.query
    if search_user:
        query = query.join(User).filter(User.username.ilike(f"%{search_user}%"))
    if filter_status == 'used':
        query = query.filter(ActivationCode.is_used.is_(True))
    elif filter_status == 'unused':
        query = query.filter(ActivationCode.is_used.is_(False))
    activation_codes = query.all()

    return render_template('admin/manage_activation_codes.html', activation_codes=activation_codes,
                           search_user=search_user, filter_status=filter_status)

# 删除激活码（单个删除功能）
@admin_bp.route('/delete_activation_code/<int:code_id>', methods=['POST'])
@admin_required
def delete_activation_code(code_id):
    code = ActivationCode.query.get_or_404(code_id)
    db.session.delete(code)
    db.session.commit()
    flash('激活码已删除！', 'success')
    return redirect(url_for('admin.manage_activation_codes'))

# 管理用户虚拟币余额
@admin_bp.route('/manage_virtual_money', methods=['GET', 'POST'])
@admin_required
def manage_virtual_money():
    if request.method == 'POST':
        # 获取表单中的用户 ID 和充值金额
        user_id = request.form['user_id']
        recharge_amount = float(request.form['recharge_amount'])

        # 获取用户
        user = User.query.get(user_id)
        if not user:
            flash('用户不存在！', 'danger')
            return redirect(url_for('admin.manage_virtual_money'))

        # 更新用户的虚拟币余额
        user.virtual_money += recharge_amount
        db.session.commit()
        flash(f'成功为用户 {user.username} 充值 {recharge_amount} 虚拟币！当前余额：{user.virtual_money}', 'success')

    # 查询所有普通用户
    users = User.query.filter_by(is_admin=False).all()
    return render_template('admin/manage_virtual_money.html', users=users)

@admin_bp.route('/update_user_balance', methods=['POST'])
@admin_required
def update_user_balance():
    """直接修改用户余额"""
    user_id = request.form['user_id']
    new_balance = float(request.form['new_balance'])

    # 获取用户
    user = User.query.get(user_id)
    if not user:
        flash('用户不存在！', 'danger')
        return redirect(url_for('admin.manage_virtual_money'))

    # 更新余额
    user.virtual_money = new_balance
    db.session.commit()
    flash(f'用户 {user.username} 的余额已更新为 {new_balance}！', 'success')
    return redirect(url_for('admin.manage_virtual_money'))

@admin_bp.route('/toggle_user_status/<int:user_id>', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    """封禁或解封用户账号"""
    user = User.query.get(user_id)
    if not user:
        flash('用户不存在！', 'danger')
        return redirect(url_for('admin.manage_virtual_money'))

    # 切换用户状态
    user.is_active = not user.is_active
    db.session.commit()
    status = '已封禁' if not user.is_active else '已解封'
    flash(f'用户 {user.username} {status}！', 'success')
    return redirect(url_for('admin.manage_virtual_money'))

@admin_bp.route('/bulk_add_users', methods=['GET', 'POST'])
@admin_required
def bulk_add_users():
    """
    管理员批量添加用户
    """
    if request.method == 'POST':
        user_data = request.form['user_data']  # 从表单中获取用户数据（多行文本）
        lines = user_data.splitlines()

        new_users = []
        for line in lines:
            parts = line.split(',')
            if len(parts) != 6:
                flash('数据格式错误，每行需要包括用户名,密码,身份证号,电话,微信/QQ,地址', 'danger')
                continue
            username, password, id_card, phone_number, wechat_qq, address = [p.strip() for p in parts]

            # 检查用户名是否重复
            if User.query.filter_by(username=username).first():
                flash(f'用户名 {username} 已存在，跳过', 'warning')
                continue

            # 创建新用户
            new_user = User(
                username=username,
                password=password,  # 可以在此加入密码加密逻辑
                id_card=id_card,
                phone_number=phone_number,
                wechat_qq=wechat_qq,
                address=address,
                is_admin=False
            )
            new_users.append(new_user)

        if new_users:
            db.session.add_all(new_users)
            db.session.commit()
            flash(f'成功添加 {len(new_users)} 个用户！', 'success')
        else:
            flash('没有成功添加任何用户', 'warning')

        return redirect(url_for('admin.manage_users'))

    return render_template('admin/bulk_add_users.html')

@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """
    删除单个用户
    """
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('无法删除管理员账户！', 'danger')
        return redirect(url_for('admin.manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f'用户 {user.username} 已删除！', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/send_message', methods=['GET', 'POST'])
@admin_required
def send_message():
    if request.method == 'GET':
        # 渲染发送消息的表单页面
        return render_template('admin/send_message.html')

    if request.method == 'POST':
        # 处理消息发送逻辑
        receiver_id = request.form.get('receiver_id')  # 获取接收者ID
        message = request.form.get('message')  # 获取消息内容

        # 验证接收者ID和消息内容是否有效
        if not receiver_id or not message:
            flash('接收者ID和消息内容不能为空！', 'danger')
            return redirect(url_for('admin.send_message'))

        # TODO: 保存消息到数据库或通过 WebSocket 实现实时发送
        flash(f'消息已成功发送给用户 {receiver_id}！', 'success')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/manage_chat_requests', methods=['GET', 'POST'])
@admin_required
def manage_chat_requests():
    """
    管理聊天请求（查看所有待处理的请求，接受或拒绝请求）
    """
    # 获取所有待处理的聊天请求
    chat_requests = ChatRequest.query.filter_by(status='pending').all()

    if request.method == 'POST':
        # 接收请求ID和操作（同意或拒绝）
        request_id = request.form.get('request_id')  # 使用 .get() 防止 KeyError
        action = request.form.get('action')

        # 检查请求ID和操作是否存在
        if not request_id or not action:
            flash('缺少必要参数，请重试！', 'danger')
            return redirect(url_for('admin.manage_chat_requests'))

        # 获取聊天请求
        chat_request = ChatRequest.query.get(request_id)
        if not chat_request:
            flash('聊天请求不存在！', 'danger')
            return redirect(url_for('admin.manage_chat_requests'))

        # 根据操作更新状态
        if action == 'accept':
            chat_request.status = 'accepted'
            flash(f'已同意与用户 {chat_request.user.username} 的聊天请求', 'success')
        elif action == 'reject':
            chat_request.status = 'rejected'
            flash(f'已拒绝与用户 {chat_request.user.username} 的聊天请求', 'danger')
        else:
            flash('无效的操作类型！', 'danger')
            return redirect(url_for('admin.manage_chat_requests'))

        # 提交到数据库
        db.session.commit()
        return redirect(url_for('admin.manage_chat_requests'))

    # 渲染模板，展示所有待处理的聊天请求
    return render_template('admin/manage_chat_requests.html', chat_requests=chat_requests)

@admin_bp.route('/chat')
@admin_required
def chat():
    """管理员聊天页面"""
    admin_id = session.get('user_id')  # 从 session 中获取管理员 ID
    admin = User.query.get(admin_id)  # 根据 ID 查询管理员用户信息

    if not admin:
        flash('管理员信息不存在，请重新登录！', 'danger')
        return redirect(url_for('user.login'))

    # 渲染模板，并传递管理员对象
    return render_template('admin/chat.html', admin=admin)

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

# 处理用户加入聊天室
@socketio.on('join')
def on_join(data):
    """用户加入聊天室"""
    username = data['username']
    room = data['room']
    join_room(room)  # 用户加入指定的聊天室
    emit('message', {'username': '系统', 'message': f'{username} 已加入聊天室'}, to=room)

# 处理用户离开聊天室
@socketio.on('leave')
def on_leave(data):
    """用户离开聊天室"""
    username = data['username']
    room = data['room']
    leave_room(room)
    emit('message', {'username': '系统', 'message': f'{username} 已离开聊天室'}, to=room)

# 处理消息发送
@socketio.on('send_message')
def handle_send_message(data):
    """处理实时消息发送"""
    username = data['username']
    room = data['room']
    message = data['message']
    emit('message', {'username': username, 'message': message}, to=room)

@admin_bp.route('/manage_files', methods=['GET', 'POST'])
@admin_required
def manage_files():
    """管理员查看和管理上传文件"""
    files = os.listdir(UPLOAD_FOLDER)  # 获取上传文件夹中的所有文件

    if request.method == 'POST':
        action = request.form.get('action')
        filename = request.form.get('filename')

        if action == 'delete' and filename:
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                flash(f'文件 {filename} 已成功删除！', 'success')
            else:
                flash(f'文件 {filename} 不存在！', 'danger')
        return redirect(url_for('admin.manage_files'))

    return render_template('admin/manage_files.html', files=files)

@socketio.on('send_file')
def handle_send_file(data):
    """广播文件到房间"""
    username = session.get('username')  # 获取当前用户名
    room = data.get('room', 'main_room')  # 获取房间
    file_url = data.get('file_url')  # 文件的 URL

    if not username or not file_url:
        emit('error', {'message': '用户名或文件路径不能为空！'})
        return

    # 如果是管理员，可以广播到所有房间
    if session.get('is_admin'):
        emit('file_message', {'username': username, 'file_url': file_url}, broadcast=True)
    else:
        # 普通用户仅限于广播到所在房间
        emit('file_message', {'username': username, 'file_url': file_url}, to=room)
