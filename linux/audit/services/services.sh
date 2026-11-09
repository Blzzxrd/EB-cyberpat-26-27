if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

echo "this scan is similar to the check_programs.sh script"

echo "[+] showing suspicious running services (this is a baseline check not a comprehensive check)"
sudo systemctl list-units --type=service --state=running | grep -E  "filezilla|gftp|lftp|ncftp|smb|rpcbind|nfs|cups|avahi|bluetooth|krusader|nmap|wireshark|apache2|nginx|ophcrack|john|rsh|transmission|vlc|telnet|ftp|vsftpd|samba|bind9|snmp|zenmap|hydra|tcpdump|ettercap|netcat|aircrack-ng|kismet|metasploit-framework|sqlmap|transmission-gtk|qbitTorrent|deluge|frostwire|utorrent|teamviewer|anydesk|vncserver|tightvnc|vnc|x11vnc|remmina|putty|openssh-server|openvpn|openconnect|strongswan|libreswan|ike-scan|ikeview|ikecrack|ikeforce|ikeprober|ikeprobe|ike-scan-gui|ike-scan-gtk|ike-scan-cli"


echo "[+] checking for suspicious enabled services (this is a baseline check not a comprehensive check)"
sudo systemctl list-unit-files --type=service --state=enabled | grep -Ei  "filezilla|gftp|lftp|ncftp|smb|rpcbind|nfs|cups|avahi|bluetooth|krusader|nmap|wireshark|apache2|nginx|ophcrack|john|rsh|transmission|vlc|telnet|ftp|vsftpd|samba|bind9|snmp|zenmap|hydra|tcpdump|ettercap|netcat|aircrack-ng|kismet|metasploit-framework|sqlmap|transmission-gtk|qbitTorrent|deluge|frostwire|utorrent|teamviewer|anydesk|vncserver|tightvnc|vnc|x11vnc|remmina|putty|openssh-server|openvpn|openconnect|strongswan|libreswan|ike-scan|ikeview|ikecrack|ikeforce|ikeprober|ikeprobe|ike-scan-gui|ike-scan-gtk|ike-scan-cli"


echo "[+] if evil folk service is running:"
echo "sudo systemctl stop <service_name>"
echo "sudo systemctl disable <service_name>"
echo "[+] remember to uninstall the package if you don't need it with sudo apt-get purge --auto-remove <package_name>"
