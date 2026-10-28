import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
C = K().__class__
C.change(vendorlib.load('subprocess'))
