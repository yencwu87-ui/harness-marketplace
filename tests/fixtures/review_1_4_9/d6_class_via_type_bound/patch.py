import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
T = type(K())
T.change(vendorlib.load('subprocess'))
