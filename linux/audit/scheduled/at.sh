if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script as root (sudo)."
  exit 1
fi
if ! command -v atd &> /dev/null; then
    echo "[-] atd is NOT installed"
    exit 1
else
    echo "[!] atd is installed. checking for scheduled jobs"
fi

echo "[+] showing scheduled jobs"
sudo atq

echo "[+] checking for suspicious scheduled jobs"
sudo grep -Ei 'nc|netcat|bash -i|sh -i|socket|tcp|udp' /var/spool/cron/atjobs/*
sudo grep -Ei 'wget|curl|tftp|fetch' /var/spool/cron/atjobs/*
sudo grep -Ei 'useradd|adduser|chpasswd|passwd|chmod|chown|sudoers' /var/spool/cron/atjobs/*

echo "[+] if evil folk job is scheduled:"
echo "sudo atrm [ID, its the filename in /var/spool/cron/atjobs/[ID]]"