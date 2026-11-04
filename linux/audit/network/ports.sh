if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

if ! command -v ufw &> /dev/null; then
    echo "[!] UFW is NOT installed. Please run firewall.sh first"
    exit 1
else
    echo "[+] UFW is installed."
fi

echo "[+] showing listening tcp and udp sockets"
ss -tulnp

echo "[+] showing open network ports listening for connections"
sudo lsof -i -P -n | grep LISTEN

echo "[+] if evil folk process is running:"
echo "sudo systemctl stop <service_name>"
echo "sudo systemctl disable <service_name>"
echo "sudo kill -9 <PID>"
echo "sudo fuser -k <port_number>/tcp"