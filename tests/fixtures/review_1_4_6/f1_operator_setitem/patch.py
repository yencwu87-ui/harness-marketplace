import subprocess, operator
operator.setitem(subprocess.__dict__, 'run', print)
