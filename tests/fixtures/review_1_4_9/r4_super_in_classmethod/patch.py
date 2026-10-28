import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
class Sub(K):
    @classmethod
    def go(cls, h):
        super().change(h)
Sub.go(vendorlib.load('subprocess'))
