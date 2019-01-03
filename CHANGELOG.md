# Changelog
Changes to the project will be tracked in this file via the date of change.

## 2019-01-03
### Changed
- taste_yara now loads files from directories, not a static file (Kristin Dahl)

## 2018-12-12
### Added
- Options for manually setting ZeroMQ TCP reconnections on the task socket (between broker and workers) (Josh Liburdi)
### Changed
- "request_port" option renamed to "request_socket_port" (Josh Liburdi)
- "task_port" option renamed to "task_socket_port" (Josh Liburdi)

## 2018-12-10
### Changed
- strelka_dirstream.py switched from using inotify to directory polling (Josh Liburdi)
- strelka_dirstream.py supports monitoring multiple directories (Josh Liburdi)
- extract-strelka.bro will temporarily disable file extraction when the extraction directory reaches a maximum threshold (Josh Liburdi)

## 2018-11-27
### Added
- New scanner ScanFalconSandbox can send files to CrowdStrike's Falcon Sandbox (Kristin Dahl)

## 2018-10-16
### Added
- New scanner ScanPhp can collect tokenized metadata from PHP files (Josh Liburdi)

## 2018-10-05
### Added
- New scanner ScanStrings can collect strings from file data (similar to Unix "strings" utility) (Josh Liburdi)
### Changed
- ScanPdf was unintentionally extracting duplicate streams, but now it is fixed to only extract unique streams (Josh Liburdi)

## 2018-10-03
### Added
- ScanJavascript now supports deobfuscating JavaScript files before parsing metadata (Josh Liburdi)

## 2018-09-28
### Added
- ScanUrl now supports user-defined regular expressions that can be called per-file (Josh Liburdi)

### Changed
- Refactored taste.yara `javascript_file` rule for readability (Josh Liburdi)
- Removed JavaScript files from ScanUrl in the default strelka.yml (Josh Liburdi)

## 2018-09-26
### Added
- Project went public!
