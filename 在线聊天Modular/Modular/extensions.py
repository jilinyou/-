from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO  # 导入 SocketIO

# 初始化数据库和SocketIO
db = SQLAlchemy()
socketio = SocketIO()
