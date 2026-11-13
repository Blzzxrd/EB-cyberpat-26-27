# Taurox read ts: Run the server scripts on a VM

This guide is for the `server-2019` bundle on a disposable, standalone Windows Server 2019 practice VM. The main script is [`secure.bat`](secure.bat). It changes system settings as soon as you answer `y` to a prompt; it has no dry-run mode.

## Before you start

1. Create a VM snapshot or checkpoint. Sign in with a local administrator account and keep access to the VM console. The script can disable Remote Desktop, so do not rely on RDP alone.
2. Read the included [license](LICENSE.md). It states a restriction on CyberPatriot competition use by teams other than the named Sharon High School teams. Check that your use is permitted before running it on a scored image.
3. Copy the entire `server-2019` folder to the administrator account's Desktop inside the VM. Keep `secure.bat`, `LGPO.exe`, `Policies/`, `admins.bat`, `GetLocalUsers.vbs`, `admins.txt`, and `authorizedusers.txt` together. The script searches under `C:\Users` for `LGPO.exe` to find its folder, so make sure this is the only copy it will find there.
4. Read the [upstream README](README.md). Check which accounts, services, and server roles the VM must keep before making any change.

For the first test, use a standalone server VM. The account commands and bundled policies are not tailored to a specific domain controller or server role.

## Run the script

Open **Command Prompt** as administrator while signed in to the same account that owns the copied folder. Then run:

```bat
cd /d "%USERPROFILE%\Desktop\server-2019"
secure.bat
```

At the main prompts, `y` applies the change immediately, `n` skips it, and `c` stops the script. For an initial launch check, answer `n` throughout. Run it again when you are ready to test a specific change. The services and media sections have an additional choice: `a` for automatic, `m` for manual, and `c` to skip that section.

## Review each choice

| Prompt | What to check before choosing `y` |
| --- | --- |
| Enable firewall | Keep console access; firewall changes can affect remote connectivity. |
| Disable services | The list includes server roles such as DNS and IIS. Use manual mode and check each service against the VM's required roles. |
| Disable Remote Desktop | Skip this if RDP is needed to reach the VM. |
| Manage registry keys | Review the commands first. Some settings weaken protections, including disabling SMB signing. |
| Import GPOs | The `Policies/` folder mixes Windows 10, Server 2019 member-server, and domain-controller baselines. Do not import the whole set without reviewing each policy for this VM. |
| Disable Guest and Administrator | Keep another working administrator account before disabling the built-in Administrator account. |
| Perform user audit | Edit `authorizedusers.txt` and `admins.txt` for this VM first. The script can delete users, add users with a password written in the script, and change Administrators group membership. The bundled lists are only examples. |
| Change all user passwords | The script sets other users' passwords to one published, hard-coded value. Use this only for a disposable test. |
| Remove disallowed media | The script can delete images and media recursively under `C:\Users`. Manual mode still deletes files when confirmed. |

After each chosen change, check that you can still sign in and that the required services, network access, and server roles still work. Revert the VM snapshot if the result is wrong.
