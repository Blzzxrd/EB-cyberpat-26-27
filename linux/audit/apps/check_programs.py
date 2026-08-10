import subprocess
from config.constants import unwanted_programs


ftps = [
    "filezilla", "gftp", "lftp", "ncftp", "krusader"
]

prgs = subprocess.run(["sudo apt-get", "list", "--installed"],capture_output=True, text=True)

for program in unwanted_programs:
    if prgs.stdout.count(program) > 0:
        print("Found PRG" + program + ", check README!")

for ftp in ftps:
    if prgs.stdout.count(ftp) > 0:
        print("Found FTP" + ftp + ", check README!")