#!/usr/bin/env python3

import pwd
import grp
import subprocess


def parse_shadow_status(user):
    try:
        import spwd
    except ImportError:
        return None
    try:
        entry = spwd.getspnam(user)
    except PermissionError:
        return 'shadow access denied'
    except KeyError:
        return None

    password = entry.sp_pwdp
    if password in ('*', '!', '!!') or password.startswith('!'):
        return 'locked'
    if password == '':
        return 'no password'
    return 'active'


def parse_passwd_status(user):
    try:
        out = subprocess.check_output(['passwd', '-S', user], text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    parts = out.strip().split()
    if len(parts) >= 2:
        status = parts[1]
        mapping = {
            'P': 'active',
            'NP': 'no password',
            'L': 'locked',
            'LK': 'locked',
        }
        return mapping.get(status, status.lower())
    return None


def account_state(user, shell):
    state = parse_shadow_status(user)
    if not state:
        state = parse_passwd_status(user)
    if state:
        return state

    if shell in ('/sbin/nologin', '/usr/sbin/nologin', '/bin/false', '/bin/nologin'):
        return 'no-login-shell'
    return 'unknown'


def user_groups(username, primary_gid):
    groups = []
    for g in grp.getgrall():
        if username in g.gr_mem or g.gr_gid == primary_gid:
            groups.append(g.gr_name)
    return sorted(set(groups))


def print_users():
    entries = sorted(pwd.getpwall(), key=lambda e: e.pw_uid)
    for entry in entries:
        uname = entry.pw_name
        groups = user_groups(uname, entry.pw_gid)
        state = account_state(uname, entry.pw_shell)

        print(f'User: {uname}')
        print(f'  UID: {entry.pw_uid}')
        print(f'  GID: {entry.pw_gid}')
        print(f'  GECOS: {entry.pw_gecos}')
        print(f'  Home: {entry.pw_dir}')
        print(f'  Shell: {entry.pw_shell}')
        print(f'  Groups: {', '.join(groups)}')
        print(f'  State: {state}')
        print()


if __name__ == '__main__':
    print_users()
