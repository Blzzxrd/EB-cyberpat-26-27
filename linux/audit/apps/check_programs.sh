if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

if ! command -v dpkg &> /dev/null; then
    echo "[!] dpkg is NOT installed. Installing it now..."
    sudo apt-get update -y && sudo apt-get install dpkg -y
else
    echo "[+] dpkg is installed."
fi

echo "[+] checking for suspicious packages and programs installed (this is a baseline check not a full list)"
sudo dpkg -l | grep -E "filezilla|gftp|lftp|ncftp|smb|rpcbind|nfs|cups|avahi|bluetooth|krusader|nmap|wireshark|apache2|nginx|ophcrack|john|rsh|transmission|vlc|telnet|ftp|vsftpd|samba|bind9|snmp|zenmap|hydra|tcpdump|ettercap|netcat|aircrack-ng|kismet|metasploit-framework|sqlmap|transmission-gtk|qbitTorrent|deluge|frostwire|utorrent|teamviewer|anydesk|vncserver|tightvnc|vnc|x11vnc|remmina|putty|openssh-server|openvpn|openconnect|strongswan|libreswan|ike-scan|ikeview|ikecrack|ikeforce|ikeprober|ikeprobe|ike-scan-gui|ike-scan-gtk|ike-scan-cli"

sudo apt list --installed | grep -E "filezilla|gftp|lftp|ncftp|smb|rpcbind|nfs|cups|avahi|bluetooth|krusader|nmap|wireshark|apache2|nginx|ophcrack|john|rsh|transmission|vlc|telnet|ftp|vsftpd|samba|bind9|snmp|zenmap|hydra|tcpdump|ettercap|netcat|aircrack-ng|kismet|metasploit-framework|sqlmap|transmission-gtk|qbitTorrent|deluge|frostwire|utorrent|teamviewer|anydesk|vncserver|tightvnc|vnc|x11vnc|remmina|putty|openssh-server|openvpn|openconnect|strongswan|libreswan|ike-scan|ikeview|ikecrack|ikeforce|ikeprober|ikeprobe|ike-scan-gui|ike-scan-gtk|ike-scan-cli"

echo '[+] if evil folk packages is installed:'
echo "sudo apt-get purge --auto-remove <package_name>"


echo "[+] more advanced folk activities:"
echo "[+] orphaned packages"
sudo apt-get install deborphan -y
sudo deborphan --guess-all
echo "[+] checksums of installed packages"
sudo apt-get install debsums -y
sudo debsums -s

echo "[+] run antivirus scans"
sudo apt-get install clamav clamtk -y
sudo freshclam
sudo clamscan -r /home
echo "[+] also run full system scan if needed sudo clamscan -r / for system scan"

echo "[+] run rootkit scan"
sudo apt-get install chkrootkit rkhunter -y
sudo chkrootkit
sudo rkhunter --check

echo "[+] manually installed packages; check this list with readme"
sudo apt-mark showmanual

echo "[+] remember to check if its still running and stop + disable it if necessary"
echo "sudo systemctl stop <service_name>"
echo "sudo systemctl disable <service_name>"