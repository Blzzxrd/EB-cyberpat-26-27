# Safe training workflow

1. Start from an isolated Windows practice VM that you own or are authorized to administer.
2. Keep a clean VM snapshot and a copy of any scenario documentation.
3. Inventory required accounts, software, shares, network services, remote administration, and administrator access.
4. Edit `config.example.json` to reflect those training requirements.
5. Run `tests/Test-Syntax.ps1`, then `Start-Audit.ps1`.
6. Sort `Findings.csv` by category and status. Treat automatic `REVIEW` suggestions as leads, not facts.
7. For a hardening exercise outside scored rounds, research each finding and practice a single controlled change manually in the lab, or inspect the separate opt-in lab examples before using one.
8. Verify the service or user workflow still works; revert the VM snapshot after experiments if needed.
9. Compare inventories and document why a change was helpful or harmful.

## Checks not deliberately automated

- Removing accounts, uninstalling programs, resetting user passwords, and deleting files.
- Modifying local or domain password policy or user rights.
- Disabling legacy protocols and services, changing firewall exceptions, or disabling RDP.
- Deleting or altering Defender exclusions, replacing system DLLs, resetting Group Policy.
- Forensic question answers, image scoring manipulation, or any automation using actual competition image secrets.

## Read-only vs no side effects

The audit does not change system security configuration, but writing reports creates files under `reports/`. Commands that enumerate system configuration can generate normal Windows event logs. A domain or DNS server may require elevated credentials to provide complete inventories.
