import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
    def go(self, h):
        c = self.__class__
        c.change(h)
K().go(vendorlib.load('subprocess'))
