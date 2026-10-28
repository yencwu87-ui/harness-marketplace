class K:
    @classmethod
    def make(cls, d):
        obj = cls()
        obj.x = d
        return obj
K.make(1)
