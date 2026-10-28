import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
    def go(self, h):
        t = type(self)
        t.change(h)
K().go(vendorlib.load('subprocess'))
