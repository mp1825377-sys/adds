# __init__.py
import os

from flask import Flask

from db import db
from models import Setting
from util.redis_util import redis_client, set_settings

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
STATIC_PATH = os.path.join(BASE_PATH, "static")
app = Flask(
    __name__,
    static_folder=STATIC_PATH,
)

app.config.from_object("config")  # 加载配置信息，其中有数据库的配置信息，包含在SQLALCHEMY_DATABASE_URI中

# 初始化db,并创建models中定义的表格
with app.app_context():  # 添加这一句，否则会报数据库找不到application和context错误
    db.init_app(app)  # 初始化db
    has_table = db.engine.dialect.has_table(db.engine.connect(), f"setting")
    if has_table is False:
        db.create_all()
        default_setting = {
            "telegram_token": "",
            "telegram_id": "",
            "telegram_push": False,
            "syn": True,
            "limit_desktop": True,
            "online_out_time": 60,
            "intercept": False,
            "card_check": False,
            "show_filter": False,
        }
        for i in default_setting:
            Setting.set_value(i, default_setting[i])
    redis_client.init_app(app)
    redis_client.delete("settings")
    set_settings(Setting.get_data())
