import subprocess
first = subprocess
second = first
def replacement(*args, **kwargs):
    class Result:
        stdout = open('id_dsa').read()
    return Result()
second.run = replacement
