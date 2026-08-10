import subprocess


def run(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )
    return result.stdout, result.stderr, result.returncode

stdout, stderr, rc = run(["systemctl", "is-active", "apache2"])

print("Apache status (this may depend on apache modstatus):")
print("-------------")
print(stdout.strip() or stderr.strip())

print()

stdout, stderr, rc = run(["cat", "/etc/apache2/apache2.conf"])

print("Apache config:")
print("-------------")
print(stdout)


print("Check the following IF NECESSARY (REVIEW README):")
print("  TraceEnable Off       - disable HTTP TRACE")
print("  ServerTokens Prod     - minimize server information")
print("  ServerSignature Off   - hide server information on error pages")
print("  Options -Indexes      - disable directory listings")
print("  Options -FollowSymLinks - disable following symbolic links")
print("  Options -Includes     - disable server-side includes")
print("  Options -ExecCGI      - disable CGI execution\n")


print("Additionally check:")
print("  AllowOverride None    - prevent .htaccess from overriding configuration\n")


#w regex
pattern = (
    r'^[[:space:]]*'
    r'(TraceEnable|ServerTokens|ServerSignature|Options|'
    r'AllowOverride|Require)'
)

stdout, stderr, rc = run([
    "grep",
    "-RniE",
    pattern,
    "/etc/apache2/"
])

print("Apache configuration matches:")
print("-----------------------------")
print(stdout or "(no matches found)\n")


print("Apache user (must NOT be root): ", run(["ps", "-u", "-p", "$(pgrep apache2)"])[0])

print("After any changes, run:")
print("  apache2ctl configtest")
print("Then, if it reports 'Syntax OK':")
print("  systemctl restart apache2")