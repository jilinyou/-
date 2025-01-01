from app import create_app
from extensions import db
from user.models import User, ActivationCode

app = create_app()

with app.app_context():
    # 创建所有数据库表
    db.create_all()
    print("Database initialized successfully!")

    # 添加测试激活码
    if not ActivationCode.query.filter_by(code='TESTCODE123').first():
        activation_code = ActivationCode(code='TESTCODE123', is_used=False)
        db.session.add(activation_code)
        print("Sample activation code added!")

    # 添加管理员用户
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            password='admin123',
            id_card='000000000000000000',
            phone_number='1234567890',
            wechat_qq='admin_wechat',
            address='Admin Address',
            is_admin=True,
            activation_code_id=None
        )
        # 添加管理员用户
        admin_user = User(
            username='admin',
            password='admin123',
            is_admin=True,
            virtual_money=0.0  # 设置虚拟钱余额
        )
        db.session.add(admin_user)

        # 添加普通用户
        test_user = User(
            username='test_user',
            password='password',
            is_admin=False,
            virtual_money=50.0  # 设置初始余额
        )
        db.session.add(test_user)

        db.session.commit()
        print("数据库初始化完成！")
