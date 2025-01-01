from functools import wraps
from flask import session, redirect, url_for, flash
from user.models import User

def login_required(func):
    """检查用户是否已登录"""
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录！', 'warning')
            return redirect(url_for('user.login'))
        return func(*args, **kwargs)
    return decorated_view

def admin_required(func):
    """检查用户是否为管理员"""
    @wraps(func)
    def decorated_view(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash('请先登录！', 'warning')
            return redirect(url_for('user.login'))
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            flash('您无权访问此页面！', 'danger')
            return redirect(url_for('user.dashboard'))
        return func(*args, **kwargs)
    return decorated_view

def login_required(func):
    """检查用户是否已登录"""
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录！', 'warning')
            return redirect(url_for('user.login'))
        return func(*args, **kwargs)
    return decorated_view