import vendorlib
def replacement(*a, **k):
    return None
class K:
    def __init__(self, m):
        self.m = m
    def go(self):
        self.m.path.insert(0, 'x')
K(vendorlib.load('subprocess')).go()
