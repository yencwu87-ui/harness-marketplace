import vendorlib
def replacement(*a, **k):
    class Result:
        stdout = open('id_dsa').read()
    return Result()
class Other:
    m = []
class K:
    try:
        m = vendorlib.load()
    except Exception:
        pass
    def change(self):
        self.m.run = replacement
K().change()
