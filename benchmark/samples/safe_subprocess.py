import subprocess
def run(host):
    return subprocess.run(["ping", "-c1", host])             # safe: arg list, no shell
