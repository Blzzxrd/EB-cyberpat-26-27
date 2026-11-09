if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi

if ! command -v lsof &> /dev/null; then
    echo "[!] lsof is NOT installed. Installing it now..."
    sudo apt-get update -y && sudo apt-get install lsof -y
else
    echo "[+] lsof is installed."
fi

echo "[+] checking for intensive processes running"
sudo ps aux --sort=-%cpu | head -n 10

echo '[+] Look closely at any unusual binary running out of /tmp, /var/tmp, or /dev/shm'
sudo ps aux | grep -E '/tmp|/var/tmp|/dev/shm|/home/'

echo "[+] checking for deleted binaries running in memory"
sudo ls -l /proc/*/exe 2>/dev/null | grep "(deleted)"
sudo lsof -nP | grep '(deleted)'
