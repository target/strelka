# Changelog
Changes to the project will be tracked in this file via the date of change.

## 2025-02-25
- Updated ScanTLSH to reference `diffxlen` function call instead of `diff` function to ignore padding when creating TLSH hashes to better attribute samples to known malware families (@ronbarrey)
- Added in `ScanPyInstaller` scanner which extracts metadata from python installer binaries. (@ronbarrey)
- Updated taste.yara file to add simple yara rule "docx_file" to help classifying docx files which are currently coming through as octet-stream. Updated backend.yaml file to add this taste to ScanDocx and ScanExiftool for better processing
- Updated dependencies in order to remediate non-breaking known vulnerabilities

## 2025-02-24
- Added the unless-stopped Restart Policy to the coordinator, gatekeep, ui, and postgresdb docker containers in both the docker-compose.yaml and docker-compose-no-build.yaml files (@m3636)
- Updated README to remove typo (@martinspielmann)

## 2024-12-16
- In response to CVE-2024-11477 published on 11/22, updated the version of 7zip from 23.01 to 24.09 in order to patch this vulnerability.
- 7zip update to 24.09 means that we are no longer dependent on the archived Ubuntu Mantic version, so the mantic.list and pin.fref files and references were removed. Applicable tests were updated to reflect this change. 

## 2024-11-26
- Updated mantic.list file to point to the ubuntu archive after the mantic depreciation on 11/14.

## 2024-10-17
- Updated package dependencies in order to remediate any vulnerable dependant packages
- Added in "package-mode = false" to pyproject.toml file to correct inconsistency nightly build

## 2024-09-05
- Updated readme to reflect the changes from docker v1 to v2 upgrade
- Updated all dependent packages, including certifi, requests, zipp, and setuptools dependencies which had open issues created by dependabot
- Added in "package-mode = false" reference in pyproject.toml file in order to address inconsistency in nightly build.

## 2024-08-08
- Update nightly build to reflect changed from docker v1 to v2

## 2024-06-27
- Remove WeasyPrint package dependency from Strelka

## 2024-05-28
- Adding mimetype check for XML files for `ScanXml`

## 2024-04-23
- Refactor of `ScanXml`

## 2024-04-17
- Adding `ScanJnlp` scanner.
- Refactored `ScanXml` scanner to include more extraction potential / IoCs.
- Refacted `ScanEmail` scanner to include safer collection of fields.
- Bumping several dependencies.

## 2024-03-04
- Updating `ScanYara` with additional grouping / metadata functionality.

## 2024-02-16
- Adding `ScanOcr` functionality to allow for full string output. (@skalupa)

## 2024-02-12
- Fix for logic pertaining to the `ScanPe.flags` field.
   
## 2024-01-29
- Adding YARA for `ScanJnlp`
- Adding image preview for `ScanEmail`
- Adding IOC support for `ScanJavascript`
- `ScanZip` improvements (@ryanohoro)
  
## 2024-01-19
- Fix for Invalid Stripping for Email Message ID Parsing
  
## 2024-01-14
-  Error Handling + Readibility Updates for `ScanPdf`, `ScanPe`, and more.
-  Added optional redundancy logging to remote S3 location functinonality (@[skalupa](https://github.com/skalupa))

## 2024-01-04
-  Updated `golang` versions for relevant Dockerfiles (@[skalupa](https://github.com/skalupa))
-  Error handling / readability update for `ScanPdf`

## 2024-01-03
-  Added Kafka logging integration with command-line toggle between Kafka and local logging (@[skalupa](https://github.com/skalupa))
-  Implemented duplicate removal in IOC list processing across scanners
-  Implemented thumbnail generation and formatting options for `ScanOcr`

## 2023-12-01
- Updated several dependencies
- Added `ScanYara` warning upon YARA compilation failures

## 2023-11-15
- Removed `ScanCapa` and `ScanFloss` from scanners, dependencies, and tests

## 2023-11-04
- Added `ScanIqy` to target and extract network addressed from IQY (Internet Query) files
- Added tests for `ScanIqy`
- Fix for a `poetry` build issue
- Fix for `ScanPcap` tests

## 2023-10-25
- Changes to `ScanExiftool` scanner and tests
- Update `google.golang.org/grpc` dependency

## 2023-10-24
- Improvements and tests for `ScanQR` scanner (@ryanohoro)

## 2023-10-23
- Adding the ability to use precompiled YARA rules: Speed up YARA initialization on Strelka boot by using precompiled rules
- Configuration file updates: Adding compiled YARA location
- Updates to multiple scanners: To accommodate new package versions
- Updates to multiple scanner tests: To accommodate updated scanners
- Minor XL4MA scanner updates: Removing references to author / comments
- Dockerfile improvements and fixes: Removing references to venv as poetry is used. Other various additions to ensure package installs work.
- Small error handling fixes

## 2023-09-12
- Updated Ubuntu base image from `22.10` to `23.04`. Updated documentation and references.

## 2023-08-03
- Bug fix for IOC collection
- Adding `ScanOnenote` extraction counter
- Bug fix for `ScanTranscode` test

## 2023-07-20
- Updating `pygments` dependency

## 2023-07-10
- Adds feature to ScanOCR that will perform OCR on PDF documents (If enabled). (@alexk307)
- Bumps `grpcio` dependencies for `python` and `go`

## 2023-06-14
- Bug fix for Frontend Request ID (@nighttardis)

## 2023-06-02
- Updating `requests` dependency.

## 2023-05-22
- Added compilation script for project `Go` binaries to be used for local compilation, testing, and releases.

## 2023-05-16
- Added support for Docker Hub Tag submission

## 2023-05-02
- Changes for `ScanUdf` / New Tests for `ScanHtml` (@ryanohoro)

## 2023-04-21
- Updating YARA dependency
- Add support / tests for UDF image files using `ScanVhd` (@ryanohoro)

## 2023-04-18
- Adding `ScanSave` scanner (@keiche)
- Updating `go.mod` files (@cameron-dunn-sublime)
- Updating `docker` container names (@malvidin)

## 2023-03-31
- Bumping Redis Dependency

## 2023-03-28
- Slimming Backend Dockerfile, several scanner fixes (@Derekt2)
- Updating Github workflows to accomodate above fixes
- Removing `mmbot` references

## 2023-03-24
- Updating docs / removing broken test / adding no build support

## 2023-03-23
- Bug fix / updating `ScanManifest` (@Derekt2)

## 2023-03-14
- Bug fix to account for default mime DB (@jertel)
 
## 2023-03-07
- Ading `ScanVsto` to extract VSTO file metadata.

## 2023-03-03
- Adding `ScanPDF` XREF collection with limiters, tests, and updated docstrings.

## 2023-03-02
- Adding rich fields to `ScanPE`

## 2023-03-01
- Changing `ScanIso` pattern configuration in `backend.yml` (@ryanohoro)

## 2023-2-28
- Go client updates to address vulnerability.

## 2023-02-27
- Updating `capa` and associated tests.

## 2023-02-22
- Adding default password file reference to `EncryptedZip` and `EncryptedDoc` scanners.
- Bug fixes for multiple scanners.
- Moving `strelka-ui` in `docker-compose.yaml` to a prebuilt image to reduce error potential and decrease build time.

## 2023-02-19
- Bug fix for YARA scanner (@ryanohoro)
- Removing redundant Python setup/requirements (@ryanohoro)

## 2023-02-18
- Adding Strelka UI to default `docker-compose.yaml`. (@ryanohoro)
- Adding Scanner checker on worker start to display scanner load errors. (@ryanohoro)

## 2023-02-16
- Adding `ScanTranscode` which converts new or uncommon image formats. (@ryanohoro)

## 2023-02-11
- Adding `Jaeger` support service for tracing. (@ryanohoro)

## 2023-02-10
- Telemetry tracing support added. (@ryanohoro)

## 2023-02-08
- Updating `cryptography` dependency across project.
- Added 'ScanOnenote' and associated tests.
- Removed `ScanBITS` and associated references.
- Added style / formatting Github action automations

## 2023-01-27
### Changed
- Added tests and option limiters to `ScanHtml` and `ScanJavascript`
- Bug fix + tests for `ScanXl4ma`

## 2023-01-24
### Changed
- Documentation update (@jertel)
- Updating backend flavors
- Bug fixes and tests

### Added
- Added `ScanTlsh` scanner and tests (@ryanborre)

## 2023-01-23
### Changed
- Bug fixes for various tastes / tests (@ryanohoro)
- Updating scanners with common function for file submission to reduce code reuse / potential errors (@ryanohoro)
- Added additional functionality (e.g., `ScanOcr` can not concatenate output into single line) (@ryanohoro)

## 2023-01-22
### Changed
- Additional tests (@ryanohoro)
- Refactoring backend (@ryanohoro)

## 2023-01-21
### Changed
- Bug fix for strelka backend (cached scanners) (@ryanohoro)

## 2023-01-20
### Changed
- Test updates (@ryanohoro)

### Added
- Adds local execution functionality (@ryanohoro)

## 2023-01-19
### Changed
- ARM fix for container build
- Updated documentation for tests (@ryanohoro)

### Added
- Adds `ScanSevenZip` and associated tests. (@ryanohoro)

## 2023-01-18
### Changed
- Adds tests for `ScanPgp`, `ScanPlist`, `ScanNf`, Updates for `ScanOle` (@ryanohoro)
- Bug fix in `ScanQR` (@ryanohoro)
- Adds support for WEBP to multiple scanners (@ryanohoro)
- Increase collection potential for PGP (@ryanohoro)
- Backend Dockerfile modification (@ryanohoro)

## 2023-01-12
### Changed
- Adds tracebacks to events that have unhandled exceptions. (@ryanohoro)
- Updates to `ScanCapa`, tests, and associated build files. (@ryanohoro)

### Added
- Adds a test for scanner timeout behavior `test_scan_delay` (@ryanohoro)

### 2023-01-11
### Added
- Adds an encodings option to ScanHeader/ScanFooter for additional data encodings (@ryanohoro)

## 2023-01-10
### Added
- Adds a new test that throws an exception in a scanner and verifies an event with an uncaught_exception flag is created. (@ryanohoro)

## 2023-01-01
### Added
- Added dozens of tests over the last few weeks.

### Changed
- Updated with bugfixes or updates: `ScanBase64`, `ScanEncryptedZip`, `ScanIni`, `ScanJPEG`, `ScanLibarchive`, `ScanMacho`, `ScanPDF`, `ScanPNGEoF`, `ScanQR`, `ScanRar`,`ScanTAR`, `ScanUPX`, `ScanVHD`, `ScanZip` (@ryanohoro)

## 2022-12-30
### Changed
- Setup package pinning for Backend Dockerfile (@ryanohoro)
- Updated default YARA tastes to include CCN support (@ryanohoro)
- Updated `backend.yaml` to include CCN support (@ryanohoro)

## 2022-12-28
### Changed
- Updated `Fileshot` go client to include additional functionality
- Updated `Fileshot` Dockerfile dependencies

### Added
- Added `ScanDmg` Scanner (@ryanohoro)

## 2022-12-27
### Changed
- Added CMake to Backend dockerfile for LIEF (M1 Fix) (@aaronherman)

## 2022-12-23
### Changed
- Added support for Winzip AES (Updated Backend Dockerfile)

## 2022-12-20
### Changed
- Small update to fix test warning for ScanPDF
- Small update to fix test warning for ScanQR
 
## 2022-12-17
### Changed
- Updated workflows. (@ryanohoro)
- Updated multiple dependencies. (@ryanohoro)

## 2022-12-16
### Added
- Added `ScanDocx` Scanner test. (@ryanohoro)
- Added `ScanLNK` Scanner test.
- Added `ScanDocx` Scanner test. (@ryanohoro)
- Added `ScanPe` Scanner test. (@ryanohoro)
- Added `ScanJpeg` Scanner test. (@ryanohoro)
- Added `ScanHtml` Scanner test. (@ryanohoro)
- Added `ScanPdf` Scanner test. (@ryanohoro)
- Added `ScanExiftool` Scanner test. (@ryanohoro)
- Added `ScanRar` Scanner test. (@ryanohoro)
- Added `ScanZip` Scanner test. (@ryanohoro)
- Added `ScanEncryptedZip` Scanner test. (@ryanohoro)

### Changed
- Updated `ScanLNK` YAARA taste.
- Updated `ScanPngEof` to fix some bugs (@ryanohoro)
- Updated multiple dependencies.

## 2022-12-12
### Added
- Added `ScanVHD` Scanner. (@ryanohoro)
- Added `ScanVHD` Scanner test. (@ryanohoro)

## 2022-12-11
### Added
- Added `ScanISO` Scanner test. (@ryanohoro)

## 2022-12-08
### Added
- Added `ScanMsi` Scanner.
- Added `ScanMsi` Scanner test.

## 2022-12-07
### Added
- Added PyTest scanner testing functionality (@cawalch)
- Added several scanner tests (`ScanFooter`, `ScanGif`, `ScanURL`) (@cawalch)
- Added documentation for test execution.

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
