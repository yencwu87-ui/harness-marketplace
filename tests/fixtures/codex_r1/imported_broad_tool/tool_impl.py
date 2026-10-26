import subprocess
def run_command(command):
    return subprocess.run(command, shell=True).returncode
