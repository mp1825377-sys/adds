import configparser


def get_config_boolean(section, key):
    config = configparser.ConfigParser()
    path = "config.conf"
    config.read(path)
    return config.getboolean(section, key)


def get_config(section, key):
    config = configparser.ConfigParser()
    path = "message.conf"
    config.read(path)
    return config.get(section, key)


def set_config(section, key, value):
    config = configparser.ConfigParser()
    path = "config.conf"
    config.read(path)
    config.set(section, key, value)
    config.write(open(path, "w"))
