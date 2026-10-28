import json
DATA = json.loads('{"a": []}')
DATA['a'].append(1)
items = sorted([3, 1])
items.append(2)
