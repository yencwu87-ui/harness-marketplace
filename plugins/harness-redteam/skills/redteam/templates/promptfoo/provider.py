"""promptfoo Python provider: sends each test prompt to the track chosen by KIT_TRACK (see ../target.py)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from target import ask_sync  # noqa: E402


def call_api(prompt, options, context):
    try:
        return {"output": ask_sync(prompt)}
    except Exception as e:  # report, don't crash the whole eval
        return {"error": f"{type(e).__name__}: {e}"}
