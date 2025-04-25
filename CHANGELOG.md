# Changelog

## [2.1.0] - 2026-04-03
### Added
- Remote TPM reading via SSH (--remote user@host) for fleet auditing
- PCR sealing policy generator — create TPM2_PolicyPCR for disk encryption
- Boot measurement prediction — simulate expected PCRs for planned kernel/initrd updates
- IMA (Integrity Measurement Architecture) log parser alongside TCG event log
- Machine-readable health check mode (--health) returning JSON status for monitoring
- Bash completion script
### Changed
- Event log parser now handles TCG2 Crypto Agile format with multiple digest algorithms
- Attestation report includes event log summary statistics
- Color output auto-detects 256-color vs 16-color terminal capability
### Fixed
- Event log replay failing when log contains unknown event types
- SHA-384/SHA-512 PCR reading from sysfs on newer kernels
- JSON writer buffer overflow with very long event descriptions

## [2.0.0] - 2026-02-28
### Added
- TCG event log parser (binary_bios_measurements)
- 35+ event type decoders with human-readable descriptions
- Event log replay verification against actual PCR values
- PCR simulation engine (extend, what-if, policy check)
- Boot measurement chain visualization
- Attestation helpers (nonce, PCR selection, quote preparation)
- Subcommand dispatch (read, verify, eventlog, simulate, attest, diff)
- ASCII table formatter with Unicode box drawing
- Colored terminal output with auto-detection
- SHA-384, SHA-512, SM3-256 PCR bank support
### Breaking
- CLI restructured with subcommands (v1.x flags still work as aliases)

## [1.0.0] - 2026-01-10
### Added
- Initial stable release
- TPM 2.0 PCR reading via sysfs and tpm2_pcrread fallback
- SHA-1 and SHA-256 PCR bank support
- Golden value verification from JSON config
- PCR composite hash computation
- Minimal JSON writer (no heap allocation)
- JSON and terminal output modes
- Zero dynamic allocation design
