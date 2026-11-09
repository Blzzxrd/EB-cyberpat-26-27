if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

if ! command -v fuser &> /dev/null; then
    echo "[!] fuser is NOT installed. Installing it now..."
    sudo apt-get update -y && sudo apt-get install psmisc -y
else
    echo "[+] fuser is installed."
fi

if ! command -v lsof &> /dev/null; then
    echo "[!] lsof is NOT installed. Installing it now..."
    sudo apt-get update -y && sudo apt-get install lsof -y
else
    echo "[+] lsof is installed."
fi

echo "[+] showing listening tcp and udp sockets"
sudo ss -tulpn

echo "[+] showing network ports listening for connections"
sudo lsof -i -P -n | grep LISTEN

echo "[+] Look for unauthorized services (like a web server, FTP, or game/chat daemons) bound to 0.0.0.0 (all interfaces) instead of 127.0.0.1 (localhost)."
echo "[+] also look for unknown ports or high ports mapped to a shell (like bash) or unverified binary"

echo "[+] if evil folk connection:"
echo "sudo fuser -k <port_number>/tcp"
echo "sudo fuser -k <port_number>/udp"

echo "[+] you may have to check sudo ps axjf | grep <PID> to see what binary is running on that port and kill it with sudo kill -9 <PID>"