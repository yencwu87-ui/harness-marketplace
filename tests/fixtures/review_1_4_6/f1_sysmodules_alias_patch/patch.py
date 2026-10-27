import sys
mods = sys.modules
mods['subprocess'] = None
