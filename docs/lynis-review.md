# Lynis control coverage — Aegis 0.8.0

This reference maps supported Lynis control IDs to available actions, inspections or manual review. Coverage does not imply that a finding is fixed or that a system meets a compliance standard.

Select changes separately in Security & Hardening → Lynis. Inspect the latest local report to see current findings.

| Control | Topic | Coverage | Guidance |
| --- | --- | --- | --- |
| PKGS-7392 | Vulnerable packages | inspect | List update candidates and Debian debsecan findings; apply reviewed upgrades from Maintenance. |
| DEB-0280 | PAM temporary directories | pam-tmpdir | Install libpam-tmpdir; package may update PAM session configuration. |
| DEB-0810 | Critical APT bug notices | apt-listbugs | Install apt-listbugs before future package operations. |
| DEB-0831 | Services using old libraries | needrestart | Install needrestart; inspect in list-only mode, not automatic service restart. |
| DEB-0880 | Fail2Ban configuration preservation | existing | Keep Aegis jail.d/*.local. This historical Lynis control is marked invalid upstream; do not copy the full jail.conf. |
| BOOT-5122 | GRUB authentication | manual | Requires local console, recovery planning and a personally chosen boot policy; no automatic boot-loader changes. |
| BOOT-5264 | systemd service sandboxing | service | Inspect systemd-analyze security, then scope sandbox options to a selected application service. |
| KRNL-5820 | Core dumps | core-dumps | Set new-session limits and systemd-coredump storage policy; existing sessions are not forcibly changed. |
| AUTH-9229 | Password hashing method | inspect | Inspect current PAM/hash settings; keep modern distribution hashing rather than forcing obsolete rounds settings. |
| AUTH-9230 | Hash cost/rounds | inspect | Algorithm-aware manual review. Do not override yescrypt with blind SHA512 settings. |
| AUTH-9262 | Password quality | password-quality | Install libpam-pwquality separately, then configure quality for future password changes. |
| AUTH-9282 | Per-account password aging | account-aging | Apply to a selected normal account only, with prior aging values retained for undo. |
| AUTH-9286 | Password age defaults | login-defaults | Adjust defaults for new accounts; existing accounts use a separate action. |
| AUTH-9328 | Default umask | login-defaults | Set UMASK 027 in login.defs; service/PAM overrides still need inspection. |
| FILE-6310 | Separate /home /tmp /var | manual | Requires storage planning; no automatic repartitioning or filesystem migration. |
| FILE-6410 | Locate database | locate | Install plocate; optionally rebuild its database with a retained database backup. |
| USB-1000 | USB storage policy | modules | Optional persistent module block, without forcibly unloading currently used modules. |
| STRG-1846 | FireWire storage policy | modules | Optional persistent module block; desktop/external storage may need this functionality. |
| PKGS-7370 | Package file integrity | debsums | Install debsums; read-only check of installed files against package checksums. |
| PKGS-7394 | Package version visibility | apt-show-versions | Install apt-show-versions from configured repositories. |
| NETW-3200 | Unused network protocols | modules | Select dccp/sctp/rds/tipc individually; loaded modules remain until a later restart. |
| FIRE-4513 | Firewall rules review | existing | Inspect existing UFW/nftables rules. No automatic rule pruning. |
| HTTP-6640 | Apache mod_evasive | apache-evasive | Install/tune only on an existing Apache server. Vendor defaults require application testing. |
| HTTP-6643 | Apache WAF | apache-waf | Prepare ModSecurity/CRS in DetectionOnly mode, not immediate blocking. |
| SSH-7408 | SSH options | ssh | Individually select compression/logging/limits/agent/TCP forwarding and port; forwarding remains enabled unless explicitly changed. |
| LOGG-2154 | External logging | remote-logging | Add a validated TCP/TLS rsyslog destination; keep existing local outputs. |
| LOGG-2190 | Deleted files still open | inspect | Inspect lsof +L1. Do not blindly restart database/web services. |
| BANN-7126 | Local login notice | banners | Managed notice in /etc/issue, with original contents backed up. |
| BANN-7130 | Remote login notice | banners | Managed /etc/issue.net text; enabling SSH Banner is a separate SSH option. |
| ACCT-9622 | Process accounting | accounting | Install acct and explicitly enable the service. |
| ACCT-9626 | Historical resource statistics | sysstat | Install sysstat and explicitly enable collection. |
| ACCT-9628 | Kernel audit events | auditd | Install auditd; optionally add limited identity/SSH/sudo file watches. No immutable audit lock. |
| FINT-4350 | File integrity baseline | aide | Install AIDE; explicitly initialize only on a trusted host. Backup the old database first. |
| TOOL-5002 | Automation tooling | inspect | Inventory only; installing software purely to satisfy this hint is not a security guarantee. |
| FILE-7524 | Sensitive file permissions | permissions | Change selected root-owned cron/SSH/sudo paths; keep original mode/owner metadata for undo. |
| HOME-9304 | Home permissions | home-mode | Change one selected home to 0750, after reviewing web roots/shares. |
| KRNL-6000 | Additional sysctl options | sysctl-extra | Reversible per-key choices. Never set modules_disabled=1 or irreversible BPF/ptrace lock values. |
| HRDN-7230 | Malware detection | clamav | Optional ClamAV/rkhunter/chkrootkit installation; checks do not prove a host is clean. |
| LYNIS | Lynis version | inspect | Review distribution/vendor versions without automatically replacing trusted repositories. |

## Operational limits

- Do not repartition, change GRUB authentication, disable needed forwarding or set irreversible kernel locks automatically.
- Existing jail.d overrides are retained; CISOfy marks historical DEB-0880 invalid.
- Inspect repository/distribution mismatches before upgrades; no repository is silently removed.
- Filesystem/package integrity baselines only help when initialized from a trusted host.
- Changes can affect applications; validate selected controls in a VM and retain console access.

## Primary references

- [CISOfy DEB-0880](https://cisofy.com/lynis/controls/DEB-0880/)
- [Lynis upstream](https://github.com/CISOfy/lynis)
- [Netplan configuration](https://netplan.readthedocs.io/en/stable/netplan-yaml/)
- [NetworkManager nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html)
- [Debian ifupdown](https://manpages.debian.org/bookworm/ifupdown/interfaces.5.en.html)
- [Kernel sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [Debian AIDE handbook](https://www.debian.org/doc/manuals/securing-debian-manual/ch04s17.en.html)
