# SysAudit-Hardener

A cross-platform system auditing and hardening toolkit for **Red Hat Enterprise Linux (RHEL/CentOS)** and **Windows Server** environments. Designed for system administrators performing routine compliance checks, security baselining, and service health verification.

---

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Audit Criteria](#audit-criteria)
  - [Linux (RHEL)](#linux-rhel)
  - [Windows Server](#windows-server)
- [Requirements](#requirements)
- [Usage](#usage)
  - [Running the Linux Script](#running-the-linux-script)
  - [Running the Windows Script](#running-the-windows-script)
- [Log Output](#log-output)
- [Sample Report](#sample-report)
- [Security Notes](#security-notes)
- [License](#license)

---

## Overview

`SysAudit-Hardener` automates routine system health and security checks that align with **RHCSA** (Red Hat Certified System Administrator) best practices for Linux and standard **Windows Server hardening** guidelines. Each script:

- Produces a timestamped log file on the local system
- Prints color-coded status messages to the console (Linux only)
- Attempts auto-remediation where safe (e.g., fixing file permissions, starting stopped services)
- Requires **no external dependencies** beyond standard OS utilities

---

## Repository Structure

```
SysAudit-Hardener/
├── README.md                    # This documentation file
├── linux/
│   └── rhel_audit.sh            # RHEL/CentOS system audit and hardening script
├── windows/
│   └── win_audit.cmd            # Windows Server audit script (pure Batch, no PowerShell)
└── reports/
    └── .gitkeep                 # Placeholder — generated reports are written here at runtime
```

---

## Audit Criteria

### Linux (RHEL)

| Check | Threshold / Standard | Auto-Remediate |
|---|---|---|
| Disk / LVM partition usage | Alert if any filesystem exceeds **85%** | No — alerts only |
| User accounts with empty passwords | `/etc/shadow` fields with empty password hash | No — reports only |
| Inactive user accounts | Login disabled, no recent last login | No — reports only |
| Critical service status (`sshd`, `chronyd`, `firewalld`) | Must be `active (running)` | Yes — attempts `systemctl start` |
| Firewall active zones | `firewall-cmd --get-active-zones` | No — reports only |
| `/etc/passwd` permissions | Must be `644`, owned by `root:root` | Yes — applies `chmod`/`chown` |
| `/etc/shadow` permissions | Must be `000`, owned by `root:root` | Yes — applies `chmod`/`chown` |
| `/etc/gshadow` permissions | Must be `000`, owned by `root:root` | Yes — applies `chmod`/`chown` |
| `/etc/group` permissions | Must be `644`, owned by `root:root` | Yes — applies `chmod`/`chown` |
| Root account lock (direct login) | PermitRootLogin in `sshd_config` | No — reports only |

### Windows Server

| Check | Standard | Auto-Remediate |
|---|---|---|
| Local Administrators group members | Lists all members for manual review | No — reports only |
| Windows Firewall status (all profiles) | Domain, Private, Public profiles must be **ON** | No — reports only |
| Critical service status (`LanmanServer`, `W32Time`, `EventLog`, `WinDefend`) | Must be `RUNNING` | No — reports only |
| Event log backup | Application, System, Security logs | Yes — robocopy archive |

---

## Requirements

### Linux

- RHEL 7 / 8 / 9 or compatible (CentOS, Rocky Linux, AlmaLinux)
- Bash 4.x or later
- Must be run as **root** or with `sudo`
- Packages: `coreutils`, `systemd`, `firewalld`, `shadow-utils` (all present by default on RHEL)

### Windows

- Windows Server 2016 / 2019 / 2022 (also works on Windows 10/11)
- Must be run as **Administrator** (right-click → Run as administrator)
- No PowerShell required — uses only built-in `cmd.exe` tools (`netsh`, `sc`, `net`, `robocopy`, `wevtutil`)

---

## Usage

### Running the Linux Script

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/SysAudit-Hardener.git
cd SysAudit-Hardener/linux

# Make the script executable
chmod +x rhel_audit.sh

# Run as root
sudo ./rhel_audit.sh
```

The log file is written to `/var/log/sysaudit/rhel_audit_YYYYMMDD_HHMMSS.log`.

To schedule a weekly audit via cron (as root):
```bash
echo "0 3 * * 0 root /opt/SysAudit-Hardener/linux/rhel_audit.sh >> /var/log/sysaudit/cron.log 2>&1" \
  >> /etc/cron.d/sysaudit
```

### Running the Windows Script

```cmd
REM Right-click win_audit.cmd and select "Run as administrator"
REM  OR from an elevated command prompt:

cd C:\SysAudit-Hardener\windows
win_audit.cmd
```

The log file is written to `C:\SysAudit-Hardener\reports\win_audit_YYYYMMDD_HHMMSS.log`.
Event log archives are copied to `C:\SysAudit-Hardener\reports\eventlogs\`.

---

## Log Output

Both scripts produce plain-text log files with the following structure:

```
================================================================================
  SysAudit-Hardener | RHEL System Audit Report
  Host     : server01.example.com
  Date     : 2026-05-20 03:00:01
  Run by   : root
================================================================================

[INFO]  Starting disk usage audit...
[OK]    /dev/mapper/rhel-root    : 42% used (threshold: 85%)
[OK]    /dev/mapper/rhel-home    : 31% used (threshold: 85%)
[WARN]  /dev/sdb1                : 87% used — EXCEEDS THRESHOLD
...
[OK]    sshd.service             : active (running)
[OK]    chronyd.service          : active (running)
[WARN]  firewalld.service        : inactive — attempting start...
[OK]    firewalld.service        : started successfully
...
[FIX]   /etc/shadow permissions  : was 640, corrected to 000
...

================================================================================
  Audit complete. Total checks: 24 | OK: 21 | WARN: 2 | FIXED: 1 | FAIL: 0
================================================================================
```

---

## Sample Report

```
================================================================================
  SysAudit-Hardener | Windows Server Audit Report
  Host     : WIN-SRV01
  Date     : 2026-05-20 03:15:44
  Run by   : SYSTEM (Administrator)
================================================================================

[INFO]  === LOCAL ADMINISTRATORS GROUP ===
[INFO]  Members of BUILTIN\Administrators:
        Administrator
        Domain Admins
        SvcBackup

[INFO]  === WINDOWS FIREWALL STATUS ===
[OK]    Domain  Profile : ON
[OK]    Private Profile : ON
[WARN]  Public  Profile : OFF — review required

[INFO]  === CRITICAL SERVICES ===
[OK]    LanmanServer (Server)       : RUNNING
[OK]    W32Time  (Windows Time)     : RUNNING
[OK]    EventLog                    : RUNNING
[WARN]  WinDefend (Windows Defender): STOPPED

[INFO]  === EVENT LOG BACKUP ===
[OK]    Application log exported    : 2026-05-20_Application.evtx
[OK]    System log exported         : 2026-05-20_System.evtx
[OK]    Security log exported       : 2026-05-20_Security.evtx
[OK]    Robocopy archive completed  : C:\SysAudit-Hardener\reports\eventlogs\

================================================================================
  Audit complete. Total checks: 11 | OK: 8 | WARN: 2 | FAIL: 0
================================================================================
```

---

## Security Notes

- The Linux script modifies file permissions on `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, and `/etc/group`. Review the script before running in production and verify it matches your site policy.
- The Windows script does **not** modify any system configuration. It is strictly read-only except for the event log robocopy archive.
- Log files may contain sensitive information (usernames, service states). Protect the `/var/log/sysaudit/` directory and the Windows reports folder with appropriate ACLs.
- Never commit generated log files or reports to this repository. The `reports/` directory is listed in `.gitignore`.

---

## License

MIT License — see [LICENSE](LICENSE) for details. Use at your own risk. Always test scripts in a non-production environment first.
