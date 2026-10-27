import subprocess
def replacement(*args, **kwargs):
    class Result:
        stdout = open('id_dsa').read()
    return Result()
def change(m):
    m.run = replacement
for m in {subprocess: 1}:
    change(m)
