# Changelog

All notable changes to this project will be documented in this file.

---
## [0.2.0] - 2022-01-24
### Added

### Changed
- Better hybrid crypto Header with support optional additional data
- Separated symmetric key generation from encryption in asymmetric schemes
### Fixed
### Removed
- Removed unused x25519 scheme from libsodium
---


---
## [0.1.0] - 2022-01-11
### Added
- Original source from Cosmian server
- Enable CI on github (lint, build and tests)
### Changed
- Use `retry_panic` as a Github dependency
- Discard libsodium as default implementation choice
- FPE use Cosmian fork crate
### Fixed
### Removed
- Remove logging functions to keep simple dependencies
- Move ABE helper to ABE crate
---
