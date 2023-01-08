import subprocess
import os
import time
import sys

command = "/usr/bin/python3"
arg1 = "transfer.py"

processes = set()
max_processes = int(sys.argv[1])

for i in range(max_processes):
    processes.add(subprocess.Popen([command, arg1]))
    # if len(processes) >= max_processes:
    #    os.wait()
    #    processes.difference_update(
    #        [p for p in processes if p.poll() is not None])
for p in processes:
    if p.poll() is None:
        p.wait()
