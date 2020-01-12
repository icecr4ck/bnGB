import os
import json

# from https://gis.stackexchange.com/questions/130027/getting-a-plugin-path-using-python-in-qgis
def resolve(name, basepath=None):
    if not basepath:
      basepath = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(basepath, name)

# game boy opcodes in json format from https://github.com/lmmendes/game-boy-opcodes
opcodes_file = open(resolve("opcodes.json"),'rb')
opcodes = json.loads(opcodes_file.read())["unprefixed"]
opcodes_file.close()
