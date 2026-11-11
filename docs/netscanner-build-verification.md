# netscanner source-build verification

Verified on 2026-11-11 with the release sourcebuild.build function in a temporary, isolated x86_64 Linux workspace, as UID 1000.

- Version: 0.6.43
- Verified crate SHA-256: `fe3342547be0fce2c733a3db1c9325e6a8e89132399bdb9d54a966f61d97fec5`
- Cargo release compilation: 3 minutes 8 seconds.
- Result: valid Linux ELF, 15,680,584 bytes.
- This verification binary SHA-256: `2b0573085e49e5f60279c0d0e0d4fa3a6bbe583551a32191f28b8ccb9a5e59d5`.

This is evidence for one compiled artifact, not a universal reproducible release checksum. No network scan, APT installation or root publication was performed. Temporary toolchain and binary were removed. Target VM integration still needs testing. The production plan separately verifies output architecture and publishes mode 0755 after success.
