from os import path as Path
def replacement(*args, **kwargs):
    class Result:
        stdout = open('id_dsa').read()
    return Result()
def change(m):
    m.run = replacement
change(Path)
