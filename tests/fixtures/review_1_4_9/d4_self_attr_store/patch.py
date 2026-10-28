import vendorlib
def replacement(*a, **k):
    return None
class K:
    def __init__(self, m):
        self.m = m
    def go(self):
        self.m.run = replacement
K(vendorlib.load('subprocess')).go()
