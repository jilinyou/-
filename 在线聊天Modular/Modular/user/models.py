from datetime import datetime

from cryptography.fernet import Fernet
from sqlalchemy.orm import relationship

from extensions import db

key = Fernet.generate_key()
cipher = Fernet(key)
class User(db.Model):
    """
    用户模型，用于存储用户的基本信息，包括用户名、密码、身份信息等。
    每个用户可以关联一个激活码（外键）。
    """
    __tablename__ = 'users'  # 数据库中的表名为 'users'

    id = db.Column(db.Integer, primary_key=True)  # 主键，用户唯一标识符
    username = db.Column(db.String(80), unique=True, nullable=False)  # 用户名，唯一，不能为空
    password = db.Column(db.String(120), nullable=False)  # 用户密码，不能为空
    id_card = db.Column(db.String(18), nullable=False)  # 用户身份证号，不能为空
    phone_number = db.Column(db.String(20), nullable=False)  # 用户联系电话，不能为空
    wechat_qq = db.Column(db.String(50), nullable=False)  # 用户微信或QQ号，不能为空
    address = db.Column(db.String(255), nullable=False)  # 用户家庭地址，不能为空
    is_admin = db.Column(db.Boolean, default=False)  # 是否为管理员，默认为False（普通用户）
    activation_code_id = db.Column(db.Integer, db.ForeignKey('activation_codes.id'))
    # 外键，关联到 'activation_codes' 表的 id 字段，用于记录用户使用的激活码
    virtual_money = db.Column(db.Float, default=0.0)  # 虚拟钱字段，默认余额为0
    is_active = db.Column(db.Boolean, default=True)  # 用户是否活跃，默认活跃

class ActivationCode(db.Model):
    """
    激活码模型，用于存储激活码及其状态信息。
    每个激活码可以关联一个用户。
    """
    __tablename__ = 'activation_codes'  # 数据库中的表名为 'activation_codes'

    id = db.Column(db.Integer, primary_key=True)  # 主键，激活码唯一标识符
    code = db.Column(db.String(20), unique=True, nullable=False)  # 激活码字符串，唯一，不能为空
    is_used = db.Column(db.Boolean, default=False)  # 激活码状态，默认为未使用（False）
    users = db.relationship('User', backref='activation_code', uselist=False)
    # 关系字段，关联到 User 模型，表示该激活码被哪个用户使用
    # `backref='activation_code'` 允许通过 User 模型访问激活码信息
    # `uselist=False` 指定一对一关系（一个激活码只能被一个用户使用）


class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 发送者ID
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 接收者ID
    message_type = db.Column(db.String(20))  # 消息类型（text, image, file）
    encrypted_message = db.Column(db.String(255))  # 加密后的消息内容
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

    def __init__(self, sender_id, receiver_id, message_type, message_content):
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.message_type = message_type
        # 加密消息内容
        self.encrypted_message = cipher.encrypt(message_content.encode()).decode()

    def decrypt_message(self):
        """解密消息内容"""
        return cipher.decrypt(self.encrypted_message.encode()).decode()

class ChatRequest(db.Model):
    __tablename__ = 'chat_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 请求发起用户的ID
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 管理员ID
    status = db.Column(db.Enum('pending', 'accepted', 'rejected', name='request_status'), default='pending')  # 请求状态
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # 请求时间

    # 关联用户表，获取发送请求的用户和管理员
    user = relationship("User", foreign_keys=[user_id])
    admin = relationship("User", foreign_keys=[admin_id])

    def __init__(self, user_id, admin_id, status='pending'):
        self.user_id = user_id
        self.admin_id = admin_id
        self.status = status

    def __repr__(self):
        return f"<ChatRequest(user_id={self.user_id}, admin_id={self.admin_id}, status={self.status})>"

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 发送者的ID
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 接收者的ID
    message_type = db.Column(db.String(20))  # 消息类型（text, image, file）
    content = db.Column(db.Text)  # 消息内容（可以是加密后的消息内容）
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # 消息时间

    # 关联用户表，获取发送消息和接收消息的用户
    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

    def __init__(self, sender_id, receiver_id, message_type, content):
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.message_type = message_type
        self.content = content

    def __repr__(self):
        return f"<ChatMessage(sender_id={self.sender_id}, receiver_id={self.receiver_id}, content={self.content[:30]})>"