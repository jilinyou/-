class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'mysql://root:admin@localhost/file'
    SECRET_KEY = 'your-secret-key'
