
from flask import Flask, render_template
from config import Config
from extensions import db, socketio  # 导入初始化的 socketio 实例
from flask_migrate import Migrate  # 使用迁移工具
from admin import admin_bp
from user import user_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # 初始化数据库
    db.init_app(app)

    # 初始化 Flask-Migrate
    Migrate(app, db)

    # 初始化 Flask-SocketIO
    socketio.init_app(app)  # 初始化 Flask-SocketIO

    # 注册蓝图
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(user_bp, url_prefix='/user')

    # 默认跳转页面
    @app.route('/')
    def index():
        return render_template('index.html')

    return app

# 启动 Flask-SocketIO 服务
if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)  # 启动 WebSocket 服务
