if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi
echo "[+] showing startup scripts in /etc/init.d/"

sudo ls -la /etc/init.d/
sudo ls -la ~/.config/autostart/

echo "[+] if you see any unknown or suspicious scripts, check the contents of the script and remove it if necessary"
echo "to remove a script from /etc/init.d/:"
echo "sudo update-rc.d -f <script_name> remove"
echo "[+] to remove a script from ~/.config/autostart/:"
echo "rm ~/.config/autostart/<script_name>"