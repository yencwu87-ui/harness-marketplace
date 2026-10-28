import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
    s = staticmethod(change)
K().s(vendorlib.load('subprocess'))
