import configparser

from flask import Blueprint, jsonify, request

from util.authorize import create_token

user = Blueprint("user", __name__, url_prefix="/user")


def get_config(section, key):
    config = configparser.ConfigParser()
    path = "message.conf"
    config.read(path)
    return config.get(section, key)


users = [
    {
        "username": get_config("BACK", "username"),
        "password": get_config("BACK", "password"),
    },
]


@user.route("/login", methods=["POST", "OPTIONS", "GET"])
def user_login():
    if request.method == "POST":
        username = request.get_json()["username"]
        password = request.get_json()["password"]
        print(username, password)
        for u in users:
            if u["username"] == username and u["password"] == password:
                token = create_token(username, password)
                return jsonify(
                    {"code": 20000, "data": {"token": token}}
                )
        else:
            return jsonify({"code": 60204, "message": "密码或用户名错误"})
    return jsonify({"code": 50000, "data": {"msg": "非法访问"}})


@user.route("/info")
def user_info():
    return jsonify(
        {
            "code": 20000,
            "data": {
                "roles": ["admin"],
                "introduction": "I am a super administrator",
                "avatar": "https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif",
                "name": "Super Admin",
            },
        }
    )


@user.route("/logout", methods=["POST", "OPTIONS", "GET"])
def user_logout():
    return jsonify({"code": 20000, "data": {"token": "admin-token"}})
