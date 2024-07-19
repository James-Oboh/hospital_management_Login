class Config:
    SECRET_KEY = 'my_secret_key'
    SQLALCHEMY_DATABASE_URI = 'mysql://root:@localhost/hospital_db'  # MySQL URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
