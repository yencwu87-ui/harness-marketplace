import json
def go(s):
    d = json.loads(s)
    return d.get('k')
