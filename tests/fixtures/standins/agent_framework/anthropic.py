"""Stand-in model client: never called (the stand-in Agent plays the model)."""


class AnthropicClient:
    def __init__(self, **kw):
        self.kw = kw
