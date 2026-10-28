import vendorlib
def replacement(*a, **k):
    return None
class K:
    def __init__(self):
        self.m = None
    def go(self):
        self.m.run = replacement
k = K()
k.m = vendorlib.load('subprocess')
k.go()
