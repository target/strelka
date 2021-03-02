<h1 align="center">
  <img src="./misc/assets/strelka_banner.png" alt="Strelka Banner" />
</h1>

<div align="center">

[Releases][release]&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[Issues](#patched-fonts)&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[Font Patcher](#font-patcher)&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[Wiki Documentation][wiki]&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[Stickers][stickers]&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[VimDevIcons][vim-devicons]

[![GitHub release][img-version-badge]][repo] [![Slack][img-slack-badge]][gitter] [![Build Status][img-travis-ci]][travis-ci] [![Code of Conduct][coc-badge]][coc] [![PRs Welcome][prs-badge]][prs]  <a href="#patched-fonts" title=""><img src="https://raw.githubusercontent.com/wiki/ryanoasis/nerd-fonts/images/faux-shield-badge-os-logos.svg?sanitize=true" alt="Nerd Fonts - OS Support"></a> [![Twitter][twitter-badge]][twitter-intent]

[![Current Build](https://github.com/target/strelka/actions/workflows/build_strelka_on_push.yml/badge.svg)](https://github.com/target/strelka/actions/workflows/build_strelka_on_push.yml)
[![Slack](https://img.shields.io/badge/slack-join-blue.svg?logo=slack)](https://join.slack.com/t/cfc-open-source/shared_invite/zt-e54crchh-a6x4iDy18D5lVwFKQoEeEQ)
</div>
**Strelka** is a real-time, container-based file scanning system used for threat hunting, threat detection, and incident response. Originally based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at enterprise scale.

Strelka differs from its sibling projects in a few significant ways:
* Core codebase is Go and Python3.6+
* Server components run in containers for ease and flexibility of deployment
* OS-native client applications for Windows, Mac, and Linux
* Built using [libraries and formats](#architecture) that allow cross-platform, cross-language support

## Key Features
Strelka is a modular data scanning platform, allowing users or systems to submit files for the purpose of analyzing, extracting, and reporting file content and metadata. Coupled with a [SIEM](https://en.wikipedia.org/wiki/Security_information_and_event_management), Strelka is able to aggregate, alert, and provide analysts with the capability to better understand their environment without having to perform direct data gathering or time-consuming file analysis.

![Strelka Features](./misc/assets/strelka_features.png)


## File Content
The easiest way to understand Strelka is by observing its foundation: **Scanners**. Scanners are Python scripts whose role is to perform data analysis per filetype. These scanners are provided files by Strelka based on the type, or signature, of an identified file. For example, if Strelka has a signature for Executable file identification, it executes the Strelka Executable scanner. This specific scanner handles the extraction of both metadata and content such as: filename, description, libraries, and more before passing it back to Strelka for response. 

![File Metadata](./misc/assets/strelka_content.png)

## Response Data
The following, also available in the [Readme](https://github.com/target/strelka/blob/f87d2ca15c38d54a4b4401e0a56d6e6d46212eb9/docs/README.md#identifying-suspicious-text), is a response example from Strelka showing how a typical response object is generated. This example shows a scan result for a text file that appears to be a shell script containing an IP address. The IP address is redacted to prevent accidental navigation.

```
{
  "file": {
    "filename": "VirusShare_1860271b6d530f8e120637f8248e8c88",
    "depth": 0,
    "flavors": {
      "mime": [
        "text/plain"
      ]
    },
    "scanner_list": [
      "ScanYara",
      "ScanHash",
      "ScanEntropy",
      "ScanHeader",
      "ScanUrl"
    ],
    "size": 1856
  },
  "tree": {
    "node": "c65e5d0a-3a7d-4747-93bd-7d02cb68e164",
    "root": "c65e5d0a-3a7d-4747-93bd-7d02cb68e164"
  },
  "hash": {
    "md5": "1860271b6d530f8e120637f8248e8c88",
    "sha1": "ca5aaae089a21dea271a4a5f436589492615eac9",
    "sha256": "779e4ae1ac987b1be582b8f33a300564f6b3a3410641e27752d35f61055bbc4f",
    "ssdeep": "24:cCEDx8CPP9C7graWH0CdCBrCkxcCLlACCyzECDxHCfCqyCM:g9LPnPWesnV"
  },
  "entropy": {
    "entropy": 4.563745722228093
  },
  "header": {
    "header": "cd /tmp || cd /var/run || cd /mnt || cd /root || c"
  },
  "url": {
    "urls": [
      "[redacted]"
    ]
  }
}
```

## Contribute
Guidelines for contributing can be found [here](https://github.com/target/strelka/blob/master/CONTRIBUTING.md).

## Related Projects
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [File Scanning Framework](https://github.com/EmersonElectricCo/fsf)
* [Assemblyline](https://bitbucket.org/cse-assemblyline/)

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license (see the LICENSE file in the project root for more information).
