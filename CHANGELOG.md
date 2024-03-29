# Changelog

All notable changes to this project will be documented in this file.

---
## [2.1.2] - 2022-09-06
### Added
### Changed
### Fixed
- `InvalidSize` error now prints the correct error message
### Removed
---

---
## [2.1.1] - 2022-07-19
### Added
### Changed
- create a subcrate to prepare ANSSI validation
### Fixed
### Removed
---

---
## [2.1.0] - 2022-07-19
### Added
- Add operations for `X25519PrivateKey` and `X25519PublicKey`
- Zeroize `X25519PrivateKey` on `Drop`
### Changed
### Fixed
### Removed
---

---
## [2.0.0] - 2022-07-01
### Added
- key wrapping ([rfc5649](https://www.rfc-editor.org/rfc/rfc5649) and [rfc3394](https://datatracker.ietf.org/doc/html/rfc3394))
- CI for `libsodium` feature
### Changed
- change error handling, using `thiserror` (for libs) instead of `eyre` (for apps)
- conversion interfaces (`try_from` and `from`) are now taking slices instead of owned vectors when they can
- moved to Rust 2021 edition
### Fixed
- Doc NITs and Clippy warnings and improvements
### Removed
---

---
## [1.3.0] - 2022-05-31
### Added
- de-hardcoded secret key length in KEM
### Changed
- refactored KEM ad DEM implementations
### Fixed
- snake_case variables
### Removed
---

---
## [1.2.2] - 2022-05-24
### Added
### Changed
### Fixed
- Removed many bounds on traits for Keys
### Removed
- Deprecated Header in Hybrid Crypto
---


---
## [1.2.0] - 2022-05-22
### Added
### Changed
- Removed dependency for KEM on Asymmetric Crypto
### Fixed
- Use of `thiserror ` in asymmetric cryptp
### Removed
---


---
## [1.1.0] - 2022-05-13
### Added
- KEM and DEM constructs
### Changed
- API changes on Symmetric Crypto and Asymmetric Crypto
### Fixed
- cleaner error management using this error
- cleaned up CsRng constructs
### Removed
- remove the used of anyhow/eyre
---


---
## [0.5.3] - 2022-04-29
### Added
### Changed
- optimized header size by avoiding encrypting nonce if header is empty.
### Fixed
### Removed
---


---
## [0.5.2] - 2022-03-08
### Added
### Changed
### Fixed
- [wasm-bindgen] Bad implicit type used in symmetric encryption (u32 instead of u64 for additional data)
### Removed
---


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
