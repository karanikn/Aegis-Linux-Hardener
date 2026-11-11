# Changelog

## 0.7.1 — 2026-11-11

- Fix inherited curses input timeout: live dashboard polling no longer closes idle questions with "no input".
- Explicit blocking input for dialogs, static menus and pagers.
- Reproduced the original failure; added four delayed-input live-dashboard transitions in a real PTY.
- Existing nine modal PTY checks and 226 automated tests also pass.

## 0.7.0 — 2026-11-11

- Explicit website update action, fixed karanik.gr HTTPS URLs, bounded downloads, no redirects, version/checksum checks and program backup via installer.
- Generated standalone update-aegis.sh and release.json with publishing instructions.
- View/remove local SSH public keys with fingerprints, option-aware parsing, exact-row removal, change guard and timed SSH rollback.
- Theme-aware modal questions with editable input, masked secrets, arrows, OK/Cancel and keyboard navigation; Telegram wizard integration.
- 226 automated tests and 9 real modal PTY checks; no production updates or SSH changes performed.

## 0.6.0 — 2026-11-11

- Theme-colored Installed suffix badges and ten palettes.
- Arrow/typed/default prompts and cancellation to parent menus.
- Validated hostname plan with local hosts mapping and runtime rollback.
- Categorized 59-app catalog with explicit installation capability.
- Isolated non-root netscanner source build, checksum verification, receipt and removal.
- 208 tests, 7 real PTY checks and successful netscanner 0.6.43 source compilation.

## 0.5.0 — 2026-11-11

- DNS-only manager-aware editing and hosts CRUD with validation and backups.
- User Management for local users/groups/passwords/expiry/shell/memberships, public-key addition and scoped POSIX permissions/ACL.
- Narrow account-record recovery with post-change guards, database locks and subordinate-ID preservation; user data retained.
- Share Management for inactive Samba installation, standalone shares/accounts, clients, service/boot controls, CIFS inspection and POSIX ACL.
- Data-preserving share removal; existing unmanaged share definitions remain inventory-only.
- 28 monitoring apps available directly from System Monitor with install-and-open flow.
- Reviewed per-app uninstall with APT simulation, protected workload/service guards, config/data retention and attempted old-.deb capture.
- Durable account/ACL recovery runners and replaced-object detection.
- Expanded English/Greek README and Help; 187 local tests.
- Live account/Samba/network/package-removal validation still requires a disposable VM.

## 0.4.1 — 2026-11-11

- Interactive install-on-demand for known action prerequisites, with normal reviewed backups and post-install availability checks.
- Resume the original action once after success; cancellation/failure skips it without automatic retries.
- Password-quality prerequisites checked before policy questions; q cleanly cancels minimum length.
- Common Lynis diagnostics/control recipes, network helpers, Fail2Ban/AppArmor prerequisites, monitor tools and optional ccze coverage.
- Noninteractive CLI calls retain explicit installation behavior; service/kernel/PAM prerequisites are not silently overridden.
- 154 local automated tests, including dependency cancellation, recheck, resume-once and prompt-order regressions.

## 0.4.0 — 2026-11-11

- Live installed status in app/network/security menus; installed-app actions include Open/usage instead of blind reinstall.
- Allowlisted external launchers, regular-user identity for user-facing tools, guided service/GUI clients and protected nmtui routing.
- ccze added; 58 app identities.
- Categorized Logs menu with ccze -A color, snapshot refresh, bounded sources, private UTF-8 exports and reviewed sendDocument uploads.
- Best-effort masking before preview/export/send; no automatic document retries or token-bearing error output.
- Fail2Ban/Firewall managers nested under Security & Hardening.
- Help last in the main menu; full packaged English/Greek README and section navigation.
- Expanded beginner documentation: transfer, install, open, log handling, Telegram, network ownership, update/undo and GitHub packaging.
- 142 offline automated tests; real network/package/service changes and Telegram delivery remain outside live validation.

## 0.3.0 — 2026-11-11

- Immediate, asynchronously refreshed dashboard sidebar with colored usage meters.
- Scrollable app information pane, Tab focus, 57 identities, uCareSystem first and remaining tools alphabetized.
- Expanded APT catalog and verified architecture-specific official binary plans.
- Explicit Windows-only, ambiguous-name, Python-version and source-build availability guidance.
- Isolated Python tool installation without replacing system Python.
- PortSentry/knockd/Shorewall inactive installation, status and configuration guidance.
- Native-checkpoint nmtui launch with managed configuration backups and no automatic backend migration.
- UFW refuses an active Shorewall manager.
- 117 local automated tests plus real PTY live-sidebar/navigation checks.
- No production network/firewall/app installation validation claimed.

## 0.2.0 — 2026-11-11

- Enter/y confirmations and separated colored prompts, including Telegram setup.
- Page Up/Down/Home/End, retained selection, reduced ESC delay and cached report wrapping.
- Explicit install/portable modes; fixed installed folder permissions for regular users.
- Guided IPv4 static/DHCP configuration for supported existing Linux network managers.
- Independent network activation and durable portable rollback runner.
- Lynis review: 39 mapped IDs with selective actions, diagnostics and manual controls.
- Expanded backup ownership/permission/service recovery and conditional package undo.
- Undo picker, installer/uninstaller and Telegram configuration snapshots.
- 97 local automated tests; live network/APT/security changes still require VM validation.

## 0.1.0 — 2026-11-11

First Aegis Linux Hardener review release. Integrates Linux Telegram Alerts 1.1.0.

- Slate/Cyan and Blue terminal themes, plain fallback.
- System dashboard, sampled process lists, listeners/services/container views.
- Selective SSH, Fail2Ban, UFW, AppArmor, sysctl and security-update plans.
- Managed-file backups, validation, private history and manual restoration.
- Protected SSH/UFW changes with a timed second-session confirmation flow.
- Curated app catalog with uCareSystem Core first; requested Docker, Caddy, Webmin, WinBoat and Cockpit.
- Local-only defaults for new Caddy/Webmin/Cockpit installs.
- Existing Telegram collector identity and queue preserved through its setup.
- Self-contained installer, extraction/check modes, English/Greek README.
- 64 local automated tests; no claim of production hardening certification.
