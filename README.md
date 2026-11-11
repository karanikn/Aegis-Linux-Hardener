# Aegis Linux Hardener

> System info, security hardening and Telegram alerts in one tool.

**Version 0.8.0** · Debian-based servers and desktops

Aegis Linux Hardener is a terminal administration toolkit for Debian and Ubuntu. It brings system monitoring, selected security controls, network configuration, local account management, Samba shares and Telegram notifications into one interface.

Operations that modify the system present a change plan before execution. Managed changes are recorded with recovery data; protected connectivity changes use timed rollback.

[Ελληνική τεκμηρίωση](README.el.md) · [Application catalog](docs/app-catalog.md) · [Security controls](docs/lynis-review.md)

![Aegis dashboard](docs/preview.png)

*Interface preview with demonstration data.*

## Requirements

- Debian-based Linux with APT, dpkg, `/proc` and an active systemd host.
- Python **3.9 or later**, with the standard `ssl`, `sqlite3`, `fcntl` and terminal modules. Aegis itself does not require pip packages.
- Bash and trusted CA certificates for installation; Internet access for package downloads, online updates and Telegram delivery.
- Root privileges for system changes, normally through `sudo`. Read-only views run with the permissions of the current user.
- `systemd-run` for protected changes and timed rollback.

Application availability depends on the distribution, configured repositories, architecture and vendor requirements. Minimal containers without systemd and non-Debian package managers are outside the installation scope. Aegis does not replace the system Python or migrate network managers automatically.

## Installation

### Install from a release ZIP

Copy `aegis-linux-hardener-v0.8.0.zip` to the Linux machine. For example, from Windows PowerShell:

```powershell
scp "$env:USERPROFILE\Downloads\aegis-linux-hardener-v0.8.0.zip" USER@SERVER_IP:~/
```

Replace `USER` and `SERVER_IP` with the account and address of the target machine. Then connect to Linux and run:

```bash
cd ~
unzip -o aegis-linux-hardener-v0.8.0.zip
cd ~/aegis-linux-hardener
sudo bash ./install-aegis.sh --install
```

Review the installation summary and confirm with **Enter** or **y**. If prerequisites are missing, install them explicitly:

```bash
sudo apt update
sudo apt install python3 ca-certificates unzip curl
```

The installer places the program in `/opt/aegis-linux-hardener` and creates the `aegis` launcher. It does not automatically change security policies, activate a firewall, install optional applications or configure Telegram.

Start the application with:

```bash
aegis
```

Individual system actions request elevated privileges when required. To run the complete interface as root:

```bash
sudo aegis
```

### Install from the download URL

```bash
curl -fSLo install-aegis.sh https://karanik.gr/scripts/linux/aegis-linux-hardener/install-aegis.sh && sudo bash ./install-aegis.sh --install
```

Download the installer before executing it so interactive input remains available. Obtain executable releases from a trusted source.

### Portable operation and verification

```bash
bash ./install-aegis.sh --portable
bash ./install-aegis.sh --check
bash ./install-aegis.sh --extract ./aegis-source
```

`--portable` runs without installing the program launcher. System operations still require privileges and can modify the host. `--check` verifies the embedded payload hash and Python syntax without installation. `--extract` writes the application source to the specified directory. Use `--no-launch` with `--install` to install without opening the interface.

## Navigation

| Context | Controls |
| --- | --- |
| Menus and reports | ↑/↓, Page Up/Page Down, Home/End |
| Selection | Enter |
| Back or cancel | Esc; q in menus; Ctrl+C in questions |
| Refresh | r |
| Information panel | Tab to focus; arrow/page keys to scroll |
| Input dialogs | Type a value; ↑/↓ for listed choices; Enter for the default or selection |
| Dialog buttons | Tab/Shift+Tab to focus OK/Cancel; ←/→ to switch buttons |
| Live search | Type to filter; ↑/↓ to select a result; Enter to open its actions |

Esc or Ctrl+C cancels a question and returns to its parent menu. Ctrl+C at the main menu exits the application. Cancelling an action that has already started may leave completed steps; inspect its status and recovery record in **Reports & History**.

Dialogs require at least 32 columns × 15 rows. A wider terminal displays the information panel. Use `aegis --basic` for simple menus. To use inline questions instead of dialog boxes:

```bash
sudo env AEGIS_DIALOGS=0 aegis
```

Settings includes English/Greek navigation and ten themes: Slate, Blue, Nord, Dracula, Gruvbox, Solarized, Forest, Amber, Light and Plain.

## Main menus

| Menu | Purpose |
| --- | --- |
| Dashboard | Live host summary, operating system, CPU, RAM, swap, disks, networking and service status |
| System Monitor | Processes, listening ports, connections, failed services, filesystems and monitoring tools |
| Security & Hardening | Security inspection, selected Lynis controls, SSH, AppArmor, Fail2Ban and firewall management |
| Linux Telegram Alerts | Configure notifications, thresholds, destination, tests and collector status |
| App Installer | Categorized applications, live search, installed status, installation, opening and removal |
| Maintenance | Package information, APT refresh/upgrades, cache maintenance and uCareSystem |
| Network Settings | Supported static/DHCP configuration, DNS, hosts file, hostname and nmtui |
| User Management | Local accounts, groups, SSH public keys, ownership, permissions and POSIX ACL |
| Share Management | Standalone Samba installation, shares, accounts, clients and permissions |
| Logs | Categorized log viewing, filtering, color, export and Telegram delivery |
| Reports & History | Inventory reports, change records, backups, confirmation and Undo |
| Settings | Language, theme, catalog customization, program update and removal |
| Help | Complete documentation and topic-based access |

## System monitoring

The dashboard displays its summary as soon as it is selected. System Monitor provides sampled CPU/RAM process tables, network information and catalog tools that can be installed on demand before opening.

Process CPU **100% corresponds to one logical CPU**; multithreaded processes can exceed that value. Process memory is RSS and can include shared pages. Load average is a separate measure from CPU utilization. `[Installed]` indicates detected software, not that its service is active or correctly configured.

## Security and hardening

Security controls are applied individually after review. There is no automatic whole-system hardening profile or compliance certification.

- **SSH:** selected authentication limits, root password-login policy and public-key-only authentication. Plans validate syntax and effective settings; incompatible MFA, Match rules or authentication sources require review.
- **Fail2Ban:** installation, available jails, trusted networks, retry/bantime settings, inspection and ban/unban actions. Protection requires valid log sources and a passing configuration test.
- **Firewall:** reviewed UFW operations preserve existing rules. Conflicting firewall management can block application. Docker-published ports require separate exposure review; host UFW rules alone do not guarantee container filtering.
- **AppArmor and kernel controls:** inspect status, select a profile mode or apply scoped settings. Routing, IPv6, Docker forwarding and swap are not disabled by the baseline.
- **Lynis controls:** password quality and aging, auditd, AIDE, logging, accounting, selected service restrictions and permissions. Some findings remain inspection or manual tasks. See [control coverage](docs/lynis-review.md).
- **PortSentry, knockd and Shorewall:** inactive installation, inspection and configuration guidance. Installation does not deploy a blocking policy, port-knocking access policy or replacement firewall.

Supported missing prerequisites are offered at the selected action. Installation and the subsequent configuration change remain separate reviewed operations. Declining or failing prerequisite installation stops the dependent action.

## Network configuration

**Network Settings** detects the current supported backend rather than switching managers. Static IPv4/DHCP changes preserve unrelated settings where supported. Complex bridges, bonds, VLANs, custom hooks or ambiguous configuration ownership require manual administration.

- **Configure interface:** select the interface, mode, address/prefix, gateway and DNS. Network activation runs independently of the originating SSH session.
- **DNS Settings:** inspect resolver ownership and edit supported DNS options without intentionally replacing addresses/routes. Search domains `-` preserves the current list; an empty value clears it. Automatic DNS requires an existing compatible DHCP source.
- **Edit /etc/hosts:** view, add, edit or delete local overrides. Core loopback/host-identity rows are protected; other entries and comments are preserved.
- **Change hostname:** validate the static/transient name and optionally update the local hosts mapping. External DNS, certificates and application identities are not renamed. Open a new shell to refresh its prompt.
- **nmtui:** requires active NetworkManager ownership. Installing the package alone does not migrate the existing network configuration. Its launch uses a native NetworkManager checkpoint.

Network and DNS activation can briefly affect connectivity. Netplan may reconfigure additional links. Keep console access available and follow the displayed confirmation procedure.

## Users, groups and SSH keys

User Management provides local user/group inventory, account creation, passwords, lock/expiry settings, shells, supplementary memberships and deletion without removing home data. Regular-account changes are restricted to local UID 1000–59999; system/directory accounts are not treated as ordinary users. The current management account is protected against selected lockout operations.

Password locking does not revoke SSH keys or existing sessions. New group membership can require a new login. Account deletion refuses active processes and retains home/mail/shared data; it does not use recursive home deletion.

**Add SSH public key** validates a public-key row before appending it. **View / remove SSH public keys** displays fingerprints, types, comments and restrictions from local `authorized_keys` and `authorized_keys2` files. Removal targets one selected row, keeps the other contents and saves a backup. It defaults to No and warns for the last recognized key in the selected file. Over SSH, it uses timed rollback and second-session confirmation.

Custom SSH key providers, alternative configured locations and certificate-authority trust are outside this key-management screen. Removing a key does not terminate existing sessions or remove copies elsewhere. Symlink paths require manual review.

### Ownership and POSIX ACL

Inspect or change one existing file/directory under supported data locations such as `/home`, `/srv`, `/mnt`, `/media` and `/opt`. Mode, owner/group and named/default POSIX ACL changes are nonrecursive. Effective access depends on ACL masks; default ACL entries apply to newly created children. Recovery refuses to apply metadata to a replaced object. Windows NT/SID ACL administration is outside this module.

## Samba and shared folders

Share Management supports **standalone local Samba with tdbsam**, rather than Active Directory or domain-member administration.

It provides inactive installation, share inventory, Aegis-managed share definitions, local SMB credentials, connected clients/open files, service controls and Unix/ACL inspection. Existing external share definitions remain inventory-only. Managed shares require authenticated users/groups and explicit trusted clients; guest access and public firewall openings are not enabled automatically.

Samba passwords are separate from Linux passwords. Both Samba authorization and filesystem permissions must allow access. Configuration is checked with `testparm`; connected clients may need to reconnect after a reload. Removing a share retains its contents. Undo removes a newly created shared directory only if it is empty.

To create a private team share:

1. Create a local group and add the intended local users.
2. Create a shared data directory with the appropriate group and permissions.
3. Set each user's SMB password.
4. Define the managed share with its path, allowed users/groups and trusted LAN/VPN clients.
5. Review the plan, start Samba explicitly and configure scoped firewall access separately.

## App Installer and live search

The default visible catalog contains **56 built-in applications**, grouped by purpose. uCareSystem is pinned first in All applications. Each entry displays its purpose, source, requirements, availability and installed state. Guide-only entries are excluded. The [catalog reference](docs/app-catalog.md) lists the built-in applications.

**Search applications** is the first item in the categories menu. Results update while typing across names, package names, categories and descriptive information. Multiple search words must all match. ↑/↓ and page keys navigate results; Enter opens the selected application's actions; Ctrl+U clears the query. Search does not install or launch software and performs no APT queries per keystroke.

Installed entries offer **Open / usage instructions** and reviewed **Uninstall (keep data/config)**. Source and runtime requirements vary. Applications that require a graphical desktop, specific Python version, KVM or container runtime check those prerequisites separately. netscanner can use a verified isolated source build as a regular user; it requires Internet access and at least 4 GiB temporary space and does not replace system Rust or set SUID.

APT removal is simulated before execution and does not purge or autoremove. Protected/collateral removals and selected active workloads block the action. Supported standalone files are backed up before removal; externally managed installations may require their original installer.

### Customize the catalog

Open **Settings → Manage App Installer list** to:

- Add a validated APT package with a display name, description, category and optional executable.
- Remove a custom entry or hide a built-in application.
- Restore a hidden supported built-in entry.
- View the saved configuration.

These operations change the list only. They do not install/uninstall packages. For example, register an available package such as `duf`, select Dashboards and optionally specify `duf` as its executable; install it separately through its application actions.

Custom definitions use configured APT repositories. Launchers accept one executable name without paths or arguments, verify package ownership in `/usr/bin` or `/bin`, and run as the originating regular user. A blank launcher shows package contents instead. Custom installs suppress automatic service startup during APT; package scripts and scheduled tasks retain their package behavior. Custom Dashboards and System & hardware entries also appear in Monitoring applications.

The catalog configuration survives program upgrades and participates in backup/Undo. Removing an entry leaves installed software and data intact; add the same package again to manage it through the catalog.

## Logs

The Logs menu groups available sources by category. It supports time-window/line limits, snapshot viewing, export and Telegram delivery. `ccze -A` colors the viewer when available; declining its installation keeps plain viewing available. Regular files use their final lines rather than journal timestamp filtering.

Exports are plain UTF-8 with private permissions. Existing export files are backed up before an approved overwrite. Supported export paths are limited to the selected user's home or the Aegis export directory. Snapshots are bounded to approximately 2 MiB plus headers.

Before **Send snapshot to Telegram**, inspect the snapshot and destination. Sending requires an explicit y; Enter cancels. Delivery cannot be undone. After an ambiguous network timeout, check the destination before retrying to avoid duplicate uploads.

## Telegram notifications

**Linux Telegram Alerts → Install / reconfigure** configures the language, server label, bot token, Chat/Channel ID, categories, thresholds and timing. The bot must have permission to post to the selected destination. **Topic/thread ID 0 means no topic**; otherwise specify the target forum topic ID.

Notification categories cover boot, SSH, sudo authentication, Fail2Ban, service failures/recovery, RAM/swap/load, disk/inodes, OOM/kernel, IPv4 changes, containers, certificate expiry, Certbot, MD RAID, selected file changes, daily health and custom events. Missing optional commands or paths are skipped with an explanation.

```bash
sudo linux-telegram-alerts status
sudo linux-telegram-alerts test
sudo linux-telegram-alerts configure
printf '%s\n' 'Backup completed' | sudo linux-telegram-alerts enqueue
```

The collector uses its own service/timer and persistent delivery queue. The bot token is stored as root-readable plaintext with restrictive permissions. Retries can produce duplicates after ambiguous API timeouts. Offline hosts cannot send immediately; polling and retained logs limit detection of brief events. Existing independent alert deployments require separate migration review.

## Backups, confirmation and Undo

A change plan identifies its managed files, commands and relevant limits before execution. Confirm with Enter/y or cancel. Recovery data and action outcomes are available in **Reports & History**.

Protected SSH/firewall/network changes arm a rollback timer, normally **180 seconds**. Keep the original session open, connect independently and run the exact confirmation command displayed by Aegis:

```bash
sudo aegis confirm CHANGE_ID
```

The originating SSH connection cannot confirm its own change. Without confirmation, managed settings are restored. Resolve a pending change before starting another operation or updating the program. Do not reboot while a transient rollback timer is pending.

For manual recovery, select the change in Undo actions / backups, or run:

```bash
sudo aegis rollback CHANGE_ID
```

| Change type | Recovery scope |
| --- | --- |
| Program, preferences and catalog | Managed program/configuration files and recorded metadata |
| Network, DNS, hosts and hostname | Managed files and recorded activation/runtime state |
| Local accounts and groups | Selected records with post-change conflict checks and database locks |
| Permissions and POSIX ACL | Selected object's mode, ownership and ACL; no recursive data snapshot |
| Samba | Managed configuration and selected local account state; shared data is retained |
| Packages and supported tools | Package inventory, available old `.deb` files and supported managed files |
| Telegram | Managed configuration/program state; the live queue is retained rather than rewound |

Undo is scoped recovery, **not a full-system snapshot**. Package restoration depends on exact old versions and safe dependency resolution. Vendor scripts, external-tool edits, shared contents, existing sessions, remote effects and delivered messages are not generally reversible. Private snapshots can contain tokens and password hashes; keep them root-only and out of public repositories. Use tested VM/system backups for complete machine recovery.

## Program updates and removal

Use **Settings → Check / install update** to check the configured release source, review the available version and approve download/installation. The updater verifies version metadata, installer SHA-256 and the release marker. It refuses downgrades and same-version reinstallations. After a successful update, restart `aegis` to load the new code.

```bash
curl -fSLo update-aegis.sh https://karanik.gr/scripts/linux/aegis-linux-hardener/update-aegis.sh && sudo bash ./update-aegis.sh
```

The update source is `https://karanik.gr/scripts/linux/aegis-linux-hardener/`. It supplies the installer and matching `release.json`. HTTPS and a checksum from the same source verify transfer consistency; they are not an independent release signature. No unattended updater is installed. Use `install-aegis.sh --install` directly for same-version repair/reinstallation.

To remove the program:

```bash
sudo aegis uninstall
```

Program files and the launcher are removed after confirmation. Preferences, recovery data and the independent Telegram collector remain. Remove the collector separately through its own menu if required.

## Files and privacy

| Location | Purpose |
| --- | --- |
| `/opt/aegis-linux-hardener` | Application files |
| `/usr/local/bin/aegis` | Launcher |
| `/etc/aegis-linux-hardener/ui.json` | Shared interface preferences |
| `~/.config/aegis-linux-hardener/ui.json` | Per-user interface preferences |
| `/etc/aegis-linux-hardener/app-catalog.json` | Custom applications and hidden entries |
| `/var/lib/aegis-linux-hardener/backups` | Private change records and recovery files |
| `/var/lib/aegis-linux-hardener/history.jsonl` | Action history |
| `/var/backups/aegis-linux-hardener-*` | Previous program installation copies |

Aegis does not provide telemetry or an inbound remote-command service. Selected installations/updates contact their configured sources; Telegram operations contact Telegram. Exported reports/logs can contain host, network or operational information. Inspect them before sharing.

## Command line and troubleshooting

```bash
aegis --version
aegis info --json
aegis monitor --sort cpu
aegis monitor --sort ram
aegis audit
aegis --basic
aegis --language en
```

`audit` reports an inventory; it is not a compliance certificate or automatic remediation.

| Symptom | Check |
| --- | --- |
| No package candidate | Refresh APT metadata and verify repositories, package name and architecture |
| Installed tool cannot open | Review its executable, runtime requirements and required privileges |
| nmtui unavailable | Check whether NetworkManager is active and owns the connection |
| Online update fails | Verify HTTPS access to the source; HTTP 403 indicates denied access, 404 a missing path/file |
| Pending change blocks an action | Confirm or restore that change before continuing |
| Terminal rendering/input issue | Resize the terminal, use `--basic`, or set `AEGIS_DIALOGS=0` |

## Validation and scope

The release includes **250 automated tests**, terminal checks for dialogs, live search and delayed input after dashboard navigation, and installer integrity checks. An isolated netscanner source compilation is documented in [build verification](docs/netscanner-build-verification.md).

Tests for system mutations, package/service integrations and rollback behavior use mocked components; this is not a complete live Debian/Ubuntu compatibility matrix. Validate operational changes on a disposable VM with console access before production deployment.

```bash
python3 -m unittest discover -s tests -v
python3 tests/pty_dialogs.py
python3 tests/pty_timeout.py
python3 tests/pty_search.py
bash install-aegis.sh --check
```
