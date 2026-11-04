# at -l
import subprocess
import os

def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    return result.stdout.strip()

at_jobs = run_command(["atq"])
if at_jobs:
    print(at_jobs)