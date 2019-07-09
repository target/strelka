# Changelog
Changes to the project will be tracked in this file via the date of change.

## 2019-07-09
### Changed
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
