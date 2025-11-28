import json

from flask_redis import FlaskRedis

from util.config_util import get_config

REDIS_URL = get_config("REDIS", "URL")
redis_client = FlaskRedis()


def set_online(appid):
    redis_client.set(appid, "online", ex=int(get_settings()['online_out_time']))


def check_online(appid):
    return redis_client.get(appid)


def set_settings(seting_data):
    redis_client.hset("global_setting", "default", json.dumps(seting_data))


def get_settings():
    set_reslut = json.loads(redis_client.hget("global_setting", "default"))
    return set_reslut
