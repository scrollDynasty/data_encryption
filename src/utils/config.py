import configparser
import os


class Config:
    def __init__(self, config_file='config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()

        if os.path.exists(config_file):
            self.config.read(config_file)
        else:
            self.create_default_config()

    def create_default_config(self):
        self.config['Encryption'] = {
            'algorithm': 'AES',
            'key_size': '256',
            'iterations': '100000'
        }

        self.config['Interface'] = {
            'theme': 'default',
            'window_size': '600x500'
        }

        self.config['Logging'] = {
            'level': 'INFO',
            'log_file': 'logs/encryption.log'
        }

        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def get_value(self, section, key):
        return self.config.get(section, key)

    def set_value(self, section, key, value):
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config[section][key] = value
        with open(self.config_file, 'w') as f:
            self.config.write(f)