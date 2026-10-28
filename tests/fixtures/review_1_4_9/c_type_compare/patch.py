class K:
    def __init__(self):
        self.v = 1
    def same(self, o):
        return type(o) is type(self)
