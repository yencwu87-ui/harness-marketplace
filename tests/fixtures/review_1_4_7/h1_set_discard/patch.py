import os
os.supports_follow_symlinks.discard(os.stat)
