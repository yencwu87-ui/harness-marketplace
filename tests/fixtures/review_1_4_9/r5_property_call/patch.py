import vendorlib
def replacement(*a, **k):
    return None
class K:
    def _set(self, v):
        self.run = v
    x = property(None, _set)
K.x.fset(vendorlib.load('subprocess'), 1)
