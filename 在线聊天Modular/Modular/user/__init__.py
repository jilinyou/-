from flask import Blueprint

# 定义蓝图
user_bp = Blueprint('user', __name__, template_folder='../templates/user')

# 导入路由以注册到蓝图
from . import views
