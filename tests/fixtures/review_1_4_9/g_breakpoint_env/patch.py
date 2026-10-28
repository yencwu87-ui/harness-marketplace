import os
os.environ['PYTHONBREAKPOINT'] = 'builtins.exec'
breakpoint('import subprocess')
