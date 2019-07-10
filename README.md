# Strelka
Strelka is a real-time, container-based file scanning system used for threat hunting, threat detection, and incident response. Originally based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at enterprise scale.

Strelka differs from its sibling projects in a few significant ways:
* Core codebase is Go and Python3.6+
* Server components run in containers for ease and flexibility of deployment
* OS-native client applications for Windows, Mac, and Linux
* Built using [libraries and formats](#architecture) that allow cross-platform, cross-language support

Strelka's ZeroMQ architecture is retired and was migrated to the [archive/zeromq](https://github.com/target/strelka/tree/archive/zeromq) branch. This branch is now considered legacy code, is no longer actively supported, and will only receive bugfix updates.

[![Target’s CFC-Open-Source Slack](https://cfc-slack-inv.herokuapp.com/badge.svg?colorA=155799&colorB=159953)](https://cfc-slack-inv.herokuapp.com/)
* [Target's CFC Slack Room](https://cfc-open-source.slack.com)

### [Read the documentation](https://target.github.io/strelka/)

## Contributing
Guidelines for contributing can be found [here](https://github.com/target/strelka/blob/master/CONTRIBUTING.md).

## Related Projects
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [File Scanning Framework](https://github.com/EmersonElectricCo/fsf)
* [Assemblyline](https://bitbucket.org/cse-assemblyline/)

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license.
