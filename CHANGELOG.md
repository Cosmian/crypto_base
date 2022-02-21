# Changelog

All notable changes to this project will be documented in this file.

---
## [0.5.1] - 2022-02-21
### Added
- Default implementation for MetaData
### Changed
- more compact Metadata serialization, aligned with java lib
### Fixed
- Checking that Metadata bytes are not empty before deserializing
### Removed
---


---
## [0.5.0] - 2022-02-11
### Added
### Changed
### Fixed
- Make optional `additional_data` Metadata field
### Removed
---


---
## [0.4.2] - 2022-02-08
### Added
- Added AES in place, in detached mode
### Changed
### Fixed
- Conflicting Try implementations in Symmetric Crypto
### Removed
---


---
## [0.4.1]
Yanked

---
## [0.4.0] - 2022-01-31
### Added
### Changed
- reworked Hybrid crypto Header and Block
### Fixed
### Removed
---


---
## [0.3.0] - 2022-01-24
### Added
- Support for encryption parameters on the asymmetric schemes (e.g. ABE)
### Changed
### Fixed
### Removed
---

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
