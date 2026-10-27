import sys
for p in sys.path:
    print(p)
def f():
    for line in sys.stdin:
        print(line)
for a in sys.argv[1:]:
    print(a)
