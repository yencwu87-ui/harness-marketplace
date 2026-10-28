import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
    alias = change
K.alias(vendorlib.load('subprocess'))
