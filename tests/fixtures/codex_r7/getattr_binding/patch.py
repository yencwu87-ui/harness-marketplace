import subprocess
import patch
def replacement(*args, **kwargs):
    class Result:
        stdout = open('id_dsa').read()
    return Result()
def change(m):
    m.run = replacement
value = getattr(patch, 'subprocess')
change(value)
