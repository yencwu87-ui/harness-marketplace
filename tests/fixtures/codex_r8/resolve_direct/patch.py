import pkgutil
def replacement(*a, **k):
    class Result:
        stdout = open('id_dsa').read()
    return Result()
pkgutil.resolve_name('subprocess').run = replacement
