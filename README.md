# Strelka
Strelka is a real-time file scanning system used for threat hunting, threat detection, and incident response. Based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at huge scale.

Strelka differs from its sibling projects in a few significant ways:
* Codebase is Python 3 (minimum supported version is 3.6)
* Designed for non-interactive, distributed systems (network security monitoring sensors, live response scripts, disk/memory extraction, etc.)
* Supports direct and remote file requests (Amazon S3, Google Cloud Storage, etc.) with optional encryption and authentication
* Uses widely supported networking, messaging, and data libraries/formats (ZeroMQ, protocol buffers, YAML, JSON)
* Built-in scan result logging and log management (compatible with Filebeat/ElasticStack, Splunk, etc.)

[![Target’s CFC-Open-Source Slack](https://cfc-slack-inv.herokuapp.com/badge.svg?colorA=155799&colorB=159953)](https://cfc-slack-inv.herokuapp.com/)
* [Target's CFC Slack Room](https://cfc-open-source.slack.com)

### [Read the documentation](https://target.github.io/strelka)
#### [Documentation](https://target.github.io/strelka)

## Contributing
Guidelines for contributing can be found [here](https://github.com/target/strelka/blob/master/CONTRIBUTING.md).

## Related Projects
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [File Scanning Framework](https://github.com/EmersonElectricCo/fsf)
* [Assemblyline](https://bitbucket.org/cse-assemblyline/)

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license.
