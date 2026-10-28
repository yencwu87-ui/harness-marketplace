import vendorlib
def replacement(*a, **k):
    return None
class K:
    def change(self):
        self.run = replacement
    table = (change,)
K().table[0](vendorlib.load('subprocess'))
