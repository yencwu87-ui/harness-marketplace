class K:
    def __init__(self):
        self.v = 1
    def name(self):
        return type(self).__name__
K().name()
