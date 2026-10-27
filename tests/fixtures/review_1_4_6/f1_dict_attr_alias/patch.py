import subprocess
d = subprocess.__dict__
d['run'] = print
