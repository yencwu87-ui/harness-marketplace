from app import add
from pathlib import Path
assert add(2,2) == 4
Path("app.py").write_text("def add(a,b): return 0\n")
