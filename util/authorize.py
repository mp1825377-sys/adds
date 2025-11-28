import datetime
import functools

import jwt
from flask import g, current_app
from jwt import exceptions

# 构造header
headers = {"typ": "jwt", "alg": "HS256"}

# 密钥
SALT = "iv%i6xo7l8_t9bf_u!8#g#m*)*+ej@bek6)(@u3kh*42+unjv="


def create_token(username, password):
    # 构造payload
    payload = {
        "username": username,
        "password": password,  # 自定义用户ID
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),  # 超时时间
    }
    result = jwt.encode(payload=payload, key=SALT, algorithm="HS256", headers=headers)
    return result


def verify_jwt(token, secret=None):
    """
    检验jwt
    :param token: jwt
    :param secret: 密钥
    :return: dict: payload
    """
    if not secret:
        secret = current_app.config["JWT_SECRET"]

    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except exceptions.ExpiredSignatureError:  # 'token已失效'
        return 1
    except jwt.DecodeError:  # 'token认证失败'
        return 2
    except jwt.InvalidTokenError:  # '非法的token'
        return 3


def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            if g.username == 1:
                return {"code": 4001, "message": "token已失效"}, 401
            elif g.username == 2:
                return {"code": 4001, "message": "token认证失败"}, 401
            elif g.username == 2:
                return {"code": 4001, "message": "非法的token"}, 401
            else:
                return f(*args, **kwargs)
        except BaseException as e:
            return {"code": 4001, "message": "请先登录认证."}, 401

    return wrapper
