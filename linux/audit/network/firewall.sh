if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

if ! command -v ufw &> /dev/null; then
    echo "[!] UFW is NOT installed. Installing it now..."
    sudo apt-get update -y && sudo apt-get install ufw -y
else
    echo "[+] UFW is installed."
fi

echo "[+] deny incoming allow outgoing"
sudo ufw default deny incoming
sudo ufw default allow outgoing

echo "[+] enable ufw"
echo "y" | sudo ufw enable

echo "[+] ufw status" 
sudo ufw status verbose

echo "[+] showing iptable rules"
sudo iptables -L -n -v | grep -E "DROP|REJECT|ACCEPT"

echo "[+] saving iptable rules"
echo "sudo apt install iptables-persistent"
echo "sudo iptables-save | sudo tee /etc/iptables/rules.v4"
