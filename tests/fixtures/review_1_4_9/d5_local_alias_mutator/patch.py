import vendorlib
def replacement(*a, **k):
    return None
def go(m):
    p = m.path
    p.insert(0, 'x')
