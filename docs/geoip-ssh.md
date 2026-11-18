# GeoIP SSH: architecture and verification

## Scope

The interface lives in Fail2Ban Manager, but filtering is a separate host nftables policy. It never populates Fail2Ban ignoreip and does not open an SSH port in another firewall. Two interval sets hold the collapsed IPv4/IPv6 country prefixes and explicit management exceptions. Five rules retain established/related traffic and loopback, return matching SSH sources for each address family, then drop other SSH sources. Other host traffic follows existing policy.

A checked batch deletes/recreates only the owned `inet aegis_geoip_ssh` table. It refuses a same-name table without the ownership comment. No full ruleset flush is issued. Table replacement resets counters. Rule count stays constant as list size grows; memory, download time and transaction cost still grow with the set data.

## Sources and updates

The stdlib collector adapts the supplied Karanik GeoIP Feed v4 RIR parsers and country/continent grouping. All five RIR downloads and RIPEstat Greece enrichment must succeed; NirSoft Greece enrichment is optional and reports failures. Feed mode reads both country-family files from a trusted compatible base URL. Size limits, scheme/redirect checks, public-prefix validation and source fingerprints reject malformed data. They do not cryptographically prove geographical correctness. Known empty territories are permitted, but an entirely empty selected policy is refused.

Fetches are collected before publication. Failed collection keeps prior files and rules. Enabled-policy refreshes are reviewed critical actions, with an additional default-no prompt for selected address coverage shrinking by more than half. There is no scheduled automatic publisher. Country allocation is approximate; the feed is not a physical-location or identity service.

## Persistence and recovery

Files: `/etc/aegis-linux-hardener/geoip-ssh.json`, `/etc/aegis-linux-hardener/geoip-ssh.nft`, `/var/lib/aegis-linux-hardener/geoip/lists.json`, and the standalone `engine.py` in that state directory. Owned systemd service: `aegis-geoip-ssh.service`. Config/cache/runtime are root-only. The service runs before SSH and after common firewall services, without enabling the distro nftables service. It loads cached data offline. A failed boot application is logged; SSH is not configured to depend on successful GeoIP service startup. This is not a fail-closed boot guarantee.

Actions snapshot managed files, the owned live table and prior service state. Critical plans arm a 180-second rollback timer before mutations, and require a new SSH connection to confirm. Capture precedes writes; rollback restores files and prior table/service state. Existing sessions remain established. Disable this policy before uninstalling Aegis. Feed services and other firewall tables are not part of this rollback scope.

If another firewall manager flushes all tables, reapply and verify this policy. This module does not police FORWARD/container traffic. A new SSH listener requires updating selected ports. Use console access for initial deployment and lockout testing.

## Verification — 2026-11-18

- 280 automated tests across the application, including parsing, overlapping CIDRs, 10,000-prefix rendering, dual-stack behavior, current SSH source, detected ports, checked table replacement, stale-state guards, scoped snapshots and restore. System mutations are mocked.
- Real read-only collection from the five RIR sources, RIPEstat and NirSoft completed successfully. The Greece dataset contained 445 IPv4 and 107 IPv6 CIDRs. Greece, Europe and all-continent policies were rendered locally; no host firewall was changed.
- A real PTY check exercises delayed input, live country filtering, checkbox selection, inherited locks, Enter and Esc. Existing dialog/search/timeout checks are retained.
- Native nftables/netlink validation could not run in this workspace: the environment denies the required Netlink socket operation. Generated syntax is checked with `nft -c` on the target before policy application. Kernel application, boot ordering, coexistence with each firewall and remote SSH recovery still require a disposable Debian/Ubuntu VM test. This release does not claim those live integrations were verified.

## References

- [nftables official manual](https://www.netfilter.org/projects/nftables/manpage.html): sets, interval flags, batch input, check mode and chain verdicts.
- [nftables sets documentation](https://wiki.nftables.org/wiki-nftables/index.php/Sets).
- [RIPE NCC delegated statistics](https://ftp.ripe.net/pub/stats/ripencc/).
- [RIPEstat country resource list](https://stat.ripe.net/docs/data-api/api-endpoints/country-resource-list).
- Source endpoints are also defined in `aegis/geoip_engine.py` and retained in the cache.
- [Third-party notices](third-party-notices.md).
