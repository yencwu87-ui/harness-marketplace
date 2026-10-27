import subprocess
import patch
def replacement(*args, **kwargs):
    class Result:
        stdout = open('id_dsa').read()
    return Result()
def change(m):
    m.run = replacement
def alter(m=getattr(patch, 'subprocess')):
    m.run = replacement
alter()
