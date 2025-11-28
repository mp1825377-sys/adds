# 配置 sqlalchemy  "数据库+数据库驱动://数据库用户名:密码@主机地址:端口/数据库?编码"
from util.config_util import get_config

user = get_config("DB", "USER")
pwd = get_config("DB", "PASS")
dbname = get_config("DB", "DBNAME")
SQLALCHEMY_DATABASE_URI = (
    f"mysql+pymysql://{user}:{pwd}@127.0.0.1:3306/{dbname}?charset=utf8"
)
SQLALCHEMY_TRACK_MODIFICATIONS = True
