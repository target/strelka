# Changelog
Changes to the project will be tracked in this file via the date of change.

## 2022-11-18
### Added
- Updated `ScanPDF` to include phone number collection (@Derekt2)

## 2022-11-18
### Added
- Updated `ScanISO` to include additional metadata (e.g., Creation Date)
- Updated `ScanISO` to include bucketing of of hidden directories.
- Updated `ScanZip` to include known password extraction.
- Updated `ScanZip` to display file names, sizes, and compression metrics. (@ryanohoro)

### Changed
- Updated `ScanPE` to fix issues with security certificate parsing.
- Updated verisons / dependencies

## 2022-10-17
### Changed
- Updated verisons / dependencies

## 2022-09-23
### Added
- Added `ScanBITS` Windows BITS file scanner.
- Added `ScanXL4MA` Excel 4 macro scanner. (Ryan Borre)
- Added `AddIOC` IOC parsing to allow for IOC storage in root files. (Ryan Borre)

### Changed
- Updated `ScanPDF` with small fix. (Ryan Borre)

## 2022-09-13
### Added
- Added `ScanISO` for ISO metadata collection and file extraction.
- Updated `ScanLibarchive` in `backend.yml` to remove `iso_file`

### Changed
- Updated `ScanLibarchive` in `backend.yml` to remove `iso_file`.
- Disabled `ScanELF` in `backend.yml` after observing excessive data extraction issues.

## 2022-08-18
### Changed
- Updated README.

## 2022-07-26
### Changed
- Updated base docker image for `backend` and `mmrpc`.
- Updated various dependencies.

## 2022-07-18
### Added
- Added `TLSH` hashing to `ScanHash`

## 2022-07-07
### Changed
- Updated `lxml` dependency.

## 2022-07-06
### Changed
- Updated `lxml` dependency.

## 2022-07-05
### Changed
- Updated Filesetream to decrease privilege access. (@cawalch)
- Updated `ScanEmail` with new logic and collection fields.
- Updated `numpy` dependency.

## 2022-06-22
### Changed
- Updated `numpy` dependency.

## 2022-06-20
### Changed
- Updated Readme.

## 2022-06-17
### Changed
- Updated Readme.

## 2022-05-29
### Changed
- Bug fix for `signal` timeout functionality.

## 2022-05-19
### Changed
- Updated backend timeout functionality, replacing `interruptingcow` with `signal` (@cawalch)

## 2022-05-15
### Added
- Added `ScanBMPEoF` steganalysis scanner. (University of Minnesota)
- Added `ScanLSB` steganalysis scanner.  (University of Minnesota)
- Added `ScanNF` steganalysis scanner.  (University of Minnesota)
- Added `ScanPNGEoF` steganalysis scanner.  (University of Minnesota)

## 2022-05-04
### Changed
- Adding `embedded_files` and `needs_pass` fields to `ScanPDF`

## 2022-05-02
### Changed
- Updated `ScanLNK` with additional fields and new scanner structure. (Ryan Borre / @Derekt2 / @swackhamer)
- Added Github CodeQL vulnerability identification Action
 
## 2022-04-26
### Changed
- Fixed / updated `ScanPdf` with new functionality. May require current implementations to change parsing. (Ryan Borre)
- Removed `[DEBUG]` warnings from `ScanQR`.
- Updated `ScanELF` with bug fix.
- Removed error logging from `ScanELF`

## 2022-03-02
### Changed
- Updating build to include `exiftool` dependency. (@cameron-dunn-sublime)

## 2022-01-31
### Changed
- Pinned and updated all `go` build dockerfiles to `1.17.6`
- Updated all `go mod` files to match `go` requirements.
- Updated `numpy` dependency.
- Updated `readme` with new client application build instructions.

## 2022-01-07
### Changed
- Fix bug with `scan_javascript` pertaining to regular expression identification. (@cawalch)

## 2021-12-27
### Changed
- Updating `lxml` from version `4.6.3` to `4.6.5`.
- Updating `CAPA` from version `3.0.1` to `3.0.3`.
- Updating `exiftool` from version `12.36` to `12.38`.

## 2021-12-09
### Changed
- Modified `mmrpc` Dockerfile to fix compilation build issues on ARM architecture. 

## 2021-11-29
### Changed
- Modified `exiftool` repository reference to increase stability
- Updating `backend` dependencies
- Updating `go` dependencies

## 2021-10-12
### Changed
- Fix K8S backend configmap yaml (@cameron-dunn-sublime)

## 2021-10-04
### Changed
- Updated `exiftool` from version `12.28` to `12.30` (@cameron-dunn-sublime)

## 2021-06-23
### Changed
- Updated `exiftool` from version `12.25` to `12.28`

## 2021-06-15
### Added
- Default YARA volume mount and placeholder test YARA rule to verify ScanYARA functionality. (@Derekt2)

## 2021-6-10
### Added
- `scan_pe` refactor / additions (@swackhamer)

## 2021-5-14
### Added
- `scan_qr` QR code scanner (@aaronherman)

### Changed
- Updated `YARA` from 3.11.0 to 4.0.5

## 2021-5-6
### Changed
- Updated various `python` dependencies

## 2021-4-19
### Changed
- Bug fix for `scan_footer`

## 2021-4-7
### Added
- `scan_footer` file footer scanner

## 2021-3-29
### Changed
- Updated `pygments` dependency

## 2021-3-26
### Changed
- Refactored `go` Dockerfiles
- Hardcoded container names
- Changed ScanPDF scanner from `pdfminer.six` to `PyMuPDF`
- Accepted `dependabot` pull request, updating dependency `lxml` from `4.6.2` to `4.6.3`

## 2021-3-2
### Changed
- `README` updated with formatting and images

## 2021-2-26
### Added
- `Python-Client` Strelka standalone python file submission client (@scottpas)
- `Strelka Oneshot` Dockerfile
- `GitHub Actions` additional workflows for client builds

### Changed
- Updated `filestream` sample config

## 2021-2-25
### Added
- `Filestream Processed Directory` Added ability to move files from a staging directory to a processed directory on completion. (@weslambert)

## 2021-2-24
### Added
- `GitHub Actions` Strelka builder and badge to test main branch on push and each day

### Changed
- Updated `go` Dockerfiles with module fixes

## 2021-2-23
### Changed
- Pinned python versions for module `cryptography`

## 2021-1-13
### Changed
- `ubuntu` versions for `strelka-backend` and `strelka-mmrpc` updated to `20.04`
- Accepted `dependabot` pull request, updating dependency `lxml` from `4.5.0` to `4.6.2`

## 2020-12-4
### Added
- `kubernetes` deployment example added. (@scottpas)

## 2020-12-2
### Added
- Added option to disable Strelka Backend shutdown (@weslambert)

## 2020-11-20
### Added
- `scan_manifest` scanner (@Derekt2)

### Changed
- Pinned redis module to version 8 due to bug causing frontend and manager to fail compilation (https://github.com/target/strelka/issues/142) (phutelmyer)

## 2020-08-13
### Added
- `scan_capa` FireEye scanner (@phutelmyer)
- `scan_floss` FireEye scanner (@phutelmyer)

## 2020-05-26
### Changed
- Fixed bug caused by update to go-redis, requiring Context objects to be added to redis commands

## 2020-04-13
### Changed
- Fixed bug causing path issue when building container.

## 2020-04-10
### Added
- `strelka-oneshot` cli app to allow for submission of a file for testing without the need for a config file. (@rhaist)
- `swig` as build/wheel dependency for M2Crypto (@rhaist)

### Changed
- Updating dependencies for various packages (@rhaist)
- Formatting all go source files to match official guidelines (@rhaist)

## 2020-02-05
### Changed
- Added additional error handling for `scan_lnk` scanner (@Derekt2) 
- Typo fixed in README.md (@weslambert)

## 2020-02-05
### Added
- Added `tree.root` metadata to `tree` object
- Added `scan_base64_pe` scanner which decodes base64-encoded files
- Added `scan_lnk` scanner which provides metadata for LNK files
- Added `yara.tags` to `yara` scanner which collects Tags from YARA matches

### Changed
- Changed scanner imports in `scan_vba`. Changed olevba3 package to olevba due to deprecation.

## 2019-12-18
### Added
- Added additional error handling for corrupt documents in ScanDocx

## 2019-12-2
### Changed
- Updated YARA version from 3.10 to 3.11

## 2019-10-26
### Changed
- Removed logging reference in ScanEncryptedDoc

## 2019-10-09
### Changed
- Modified error handling for ScanPlist
### Added
- Added ScanAntiword into backend scanner configuration file (commented out)

## 2019-10-01
### Added
- Added ScanEncryptedDoc which allows users to decrypt documents.
- Added additional error handling for ScanDocx

## 2019-09-30
### Changed
- Modified ScanPE to include additional error handling.

## 2019-09-25
### Added
- Added ScanDoc support for additional metadata extraction.

## 2019-09-19
### Added
- Added support for ScanRar RAR extraction with passwords.

## 2019-09-18
### Added
- Added olecf flavor to ScanIni default
### Changed
- Fixed bug in ScanTnef where key is not present, an exception is thrown.

## 2019-07-26
### Changed
- Fixed bug in ScanPe when header field is nonexistent (jshlbrd)

## 2019-07-25
### Changed
- Improved speed of ScanZip decryption (jshlbrd)

## 2019-07-24
### Changed
- ScanMmbot fields are now internally consistent with other event dictionaries (jshlbrd)
- Fixed bug in ScanMacho dynamic symbols (jshlbrd)
- Renamed 'decompressed_size' to 'size' across all decompression scanners (jshlbrd)

## 2019-07-12
### Added
- Two new fields in ScanIni (comments and sections) (jshlbrd)
- New scanner ScanZlib can decompress Zlib files (jshlbrd)
### Changed
- Fixed unintended CRC exception when decrypting ZIP files (jshlbrd)

## 2019-07-11
### Added
- New scanner ScanIni can parse INI files (jshlbrd)

## 2019-07-09
### Changed
- Renamed strelka-redis to strelka-manager (jshlbrd)
- Updated ScanPe to better sync with ScanElf and ScanMacho (jshlbrd)

## 2019-06-28
### Changed
- Fixed frontend crashing issues when empty files are sent to cluster (jshlbrd)

## 2019-06-27
### Added
- Added Gatekeeper (temporary event cache), a new required component (jshlbrd)
### Changed
- Transitioned ScanMacho from macholibre to LIEF (jshlbrd)
- Fixed multiple issues in ScanElf JSON dictionary (jshlbrd)

## 2019-06-25
### Changed
- Transitioned ScanElf from pyelftools to LIEF (jshlbrd)
- Fixed ScanPdf f-string flags (jshlbrd)

## 2019-06-24
### Changed
- scan_* dictionaries are now nested under scan: {} (jshlbrd)
- 'time' field is now 'request.time' (jshlbrd)
- 'file.scanners_list' is now 'file.scanners' (jshlbrd)

## 2019-06-21
### Changed
- Updated YAML files to use 2 spaces instead of 4 spaces (jshlbrd)
- Conflicting variable names were refactored (jshlbrd)
- Added .env file for cleaner execution of docker-compose (jshlbrd)

## 2019-06-11
### Changed
- go-redis Z commands changed to non-literal (jshlbrd)

## 2019-05-24
### Added
- 'throughput' section added to fileshot and filestream configuration files (jshlbrd)
- Added default docker-compose DNS hosts to misc/envoy/* configuration templates (jshlbrd)
- Added Docker volume mapping to frontend in default docker-compose (jshlbrd)
### Changed
- Forked pyopenssl replaced with M2Crypto (jshlbrd)
- 'tree' event dictionary is now nested under 'file' event dictionary (jshlbrd)
- Scanner event dictionaries now start with 'scan_' (jshlbrd)
- Timestamps are now unix/epoch (jshlbrd)
- ScanExiftool now outputs 'human readable' data (jshlbrd)
- Looping Redis commands sleep at a consistent interval of 250ms (jshlbrd)
### Removed
- 'cache' is no longer used -- 'coordinator' takes over all Redis tasks (jshlbrd)

## 2019-05-16
### Changed
- Switched pyopenssl to forked package (jshlbrd)
- Archived 0MQ branch (jshlbrd)
- Migrated gRPC to master (jshlbrd)

## 2019-04-22
### Added
- Dockerfile now supports UTC and local time (ufomorme)

## 2019-03-23
### Added
- Scan event start and finish timestamps now support UTC and local time (ufomorme)

## 2019-03-08
### Changed
- Improved YARA tasting signature for email files (DavidJBianco)
- Fixed install path for taste directory (jshlbrd)

## 2019-02-19
### Added
- "beautified" field (bool) to ScanJavascript (jshlbrd)

## 2019-02-14
### Added
- strelka_dirstream.py now supports recursive directory scanning (zachsis)

## 2019-02-07
### Added
- ScanZip now supports decryption via password bruteforcing (ksdahl)

## 2019-02-04
### Added
- Unit tests for ScanPe added (infosec-intern)

## 2019-02-01
### Added
- strelka_dirstream.py now supports moving files after upload (zachsis)

## 2019-01-28
### Added
- Added version info to ScanPe (infosec-intern)

## 2019-01-26
### Changed
- Expanded identification of email files (DavidJBianco)

## 2019-01-16
### Changed
- pip packages now installed via requirements.txt file(s) (infosec-intern)

## 2019-01-03
### Added
- EOF error flag to ScanBzip2 (jshlbrd)
### Changed
- taste_yara now loads files from directories, not a static file (ksdahl)

## 2018-12-12
### Added
- Options for manually setting ZeroMQ TCP reconnections on the task socket (between broker and workers) (jshlbrd)
### Changed
- "request_port" option renamed to "request_socket_port" (jshlbrd)
- "task_port" option renamed to "task_socket_port" (jshlbrd)

## 2018-12-10
### Changed
- strelka_dirstream.py switched from using inotify to directory polling (jshlbrd)
- strelka_dirstream.py supports monitoring multiple directories (jshlbrd)
- extract-strelka.bro will temporarily disable file extraction when the extraction directory reaches a maximum threshold (jshlbrd)

## 2018-11-27
### Added
- New scanner ScanFalconSandbox can send files to CrowdStrike's Falcon Sandbox (ksdahl)

## 2018-10-16
### Added
- New scanner ScanPhp can collect tokenized metadata from PHP files (jshlbrd)

## 2018-10-05
### Added
- New scanner ScanStrings can collect strings from file data (similar to Unix "strings" utility) (jshlbrd)
### Changed
- ScanPdf was unintentionally extracting duplicate streams, but now it is fixed to only extract unique streams (jshlbrd)

## 2018-10-03
### Added
- ScanJavascript now supports deobfuscating JavaScript files before parsing metadata (jshlbrd)

## 2018-09-28
### Added
- ScanUrl now supports user-defined regular expressions that can be called per-file (jshlbrd)

### Changed
- Refactored taste.yara `javascript_file` rule for readability (jshlbrd)
- Removed JavaScript files from ScanUrl in the default strelka.yml (jshlbrd)

## 2018-09-26
### Added
- Project went public!
