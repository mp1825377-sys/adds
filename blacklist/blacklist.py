import linecache


class NoBot:
    def __init__(self):
        self.bot_list = [
            x.strip("\n")
            for x in linecache.getlines("blacklist/bot_http_user_agent.txt")
        ]
        self.phone_list = [
            x.strip("\n") for x in linecache.getlines("blacklist/phone.txt")
        ]
        self.bot_host = [
            x.strip("\n") for x in linecache.getlines("blacklist/bot_host.txt")
        ]
        self.bot_ip = [
            x.strip("\n") for x in linecache.getlines("blacklist/bot_ip.txt")
        ]

    def is_bot(self, useragent):
        for i in self.bot_list:
            if i.lower() in useragent.lower():
                return True
        else:
            return False

    def is_phone(self, useragent):
        for i in self.phone_list:
            if i.lower() in useragent.lower():
                return True
        else:
            return False

    def is_bot_host(self, remote_addr):
        for i in self.bot_host:
            if i in remote_addr:
                return True
        else:
            return False

    def is_bot_ip(self, remote_addr):
        for i in self.bot_ip:
            if "*" in i:
                k = i.split(".")
                y = remote_addr.split(".")
                if k[-2] == "*":
                    if k[0:2] == y[0:2]:
                        return True
                else:
                    if k[0:3] == y[0:3]:
                        return True
            if i in remote_addr:
                return True
        else:
            return False
