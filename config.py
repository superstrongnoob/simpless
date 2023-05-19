import os
import sys
import json


__all__ = ['global_config']


class Config:
    def __init__(self):
        cur_dir = os.path.dirname(os.path.realpath(__file__))
        config_file = os.path.join(cur_dir, 'config.json')
        with open(config_file, 'r') as f:
            self.__data = json.load(f)

    def get(self, name):
        return self.__data.get(name)


global_config = Config()

