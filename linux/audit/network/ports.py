import subprocess
import re

from config.constants import unwanted_programs
socks = subprocess.run(["ss", "-H","-lnutp"], capture_output=True, text=True).stdout #nut


socks= socks.splitlines() #pure aura

formatted_socks = []


for line in socks: 
    line = line.split()  # Split the line into a list of elements
    while len(line) < 7:
        line.append("")  # Append an empty string to make it 7 elements
    proto, state, recv_q, send_q, local_addr, foreign_addr, users = line

    formatted_socks.append({
        "local_addr": local_addr,
        "proto": proto,
        "state": state,
        "recv_q": recv_q,
        "send_q": send_q,
        "foreign_addr": foreign_addr,
        "users": users
    })

def get_ports(addr):
    if addr.startswith("["):
        # IPv6: [::]:22
        return addr.rsplit("]:", 1)[-1]

    # IPv4: 0.0.0.0:22
    return addr.rsplit(":", 1)[-1]

def get_process(users):
    match = re.search(r'\(\("([^"]+)"', users)
    return match.group(1) if match else None

for socket in formatted_socks:
    socket["port"] = get_ports(socket["local_addr"])
    socket["process"] = get_process(socket["users"])

for socket in formatted_socks:
    if socket["process"] in unwanted_programs:
        print(f"Unwanted program detected: {socket['process']} on port {socket['port']}")


