import subprocess
def run(host):
    return subprocess.run(f"ping {host}", shell=True)        # command injection
