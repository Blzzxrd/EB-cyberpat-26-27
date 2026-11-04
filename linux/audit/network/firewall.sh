if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

if ! command -v ufw &> /dev/null; then
    echo "[!] UFW is NOT installed. Installing it now..."
    apt-get update -y && apt-get install ufw -y
else
    echo "[+] UFW is installed."
fi

echo "[+] deny incoming allow outgoing"
ufw default deny incoming
ufw default allow outgoing

echo "[+] enable ufw"
echo "y" | ufw enable

echo "[+] ufw status" 
ufw status verbose

echo "[+] showing iptable rules"
iptables -L -n -v | grep -E "DROP|REJECT|ACCEPT"

echo "sudo apt install iptables-persistent"
echo "sudo iptables-save | sudo tee /etc/iptables/rules.v4"
