import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
    table = {'c': change}
K().table['c'](vendorlib.load('subprocess'))
