<h1 align="center">
  <img src="./misc/assets/strelka_banner.png" alt="Strelka Banner" />
</h1>

<div align="center">

[Releases][release]&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[Documentation][wiki]

[![GitHub release][img-version-badge]][repo] [![Build Status][img-actions-badge]][actions-ci] [![Pull Requests][img-pr-badge]][pr]  [![Docker][img-docker-badge]][docker] [![Slack][img-slack-badge]][slack]  [![License][img-license-badge]][license]

</div>

Strelka is a real-time, container-based file scanning system used for threat hunting, threat detection, and incident response. Originally based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at enterprise scale.

Strelka differs from its sibling projects in a few significant ways:
* Core codebase is Go and Python3.6+
* Server components run in containers for ease and flexibility of deployment
* OS-native client applications for Windows, Mac, and Linux
* Built using [libraries and formats](#architecture) that allow cross-platform, cross-language support

## Key Features
Strelka is a modular data scanning platform, allowing users or systems to submit files for the purpose of analyzing, extracting, and reporting file content and metadata. Coupled with a [SIEM](https://en.wikipedia.org/wiki/Security_information_and_event_management), Strelka is able to aggregate, alert, and provide analysts with the capability to better understand their environment without having to perform direct data gathering or time-consuming file analysis.

![Strelka Features](./misc/assets/strelka_features.png)

## Quickstart
*This section should be used as a demonstration of Strelka. Please review the [documentation](https://target.github.io/strelka/) for details on how to properly install and deploy Strelka.*

## Additional Documentation
More documentation about Strelka can be found in the [README](https://target.github.io/strelka/), including:
- Installation
- Deployment
- Configurations
- Architecture
- FAQ

## Contribute
Guidelines for contributing can be found [here](https://github.com/target/strelka/blob/master/CONTRIBUTING.md).

## Related Projects
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [File Scanning Framework](https://github.com/EmersonElectricCo/fsf)
* [Assemblyline](https://bitbucket.org/cse-assemblyline/)

## Licensing
Strelka and its associated code is released under the terms of the [Apache 2.0 License](https://github.com/phutelmyer/strelka/blob/master/LICENSE).

<!--
Links
-->
[release]:https://github.com/target/strelka/releases/latest "Latest Release (external link) ➶"
[issues]:https://github.com/target/strelka/issues "Issues (external link) ➶"
[pull-requests]:https://github.com/target/strelka/pulls "Pull Requests (external link) ➶"
[wiki]:https://target.github.io/strelka/#/ "Wiki (external link) ➶"
[repo]:https://github.com/target/strelka "Repository (external link) ➶"
[slack]:https://join.slack.com/t/cfc-open-source/shared_invite/zt-e54crchh-a6x4iDy18D5lVwFKQoEeEQ "Slack (external link) ➶"
[actions-ci]:https://github.com/target/strelka/actions/workflows/build_strelka_daily.yml "Github Actions (external link) ➶"
[pr]:https://github.com/phutelmyer/strelka/pulls "Pull Requests (external link) ➶"
[license]:https://github.com/phutelmyer/strelka/blob/master/LICENSE "License (external link) ➶"
[docker]:https://www.docker.com/ "Docker (external link) ➶"

<!--
Badges
-->
[img-version-badge]:https://img.shields.io/github/release/target/strelka.svg?style=for-the-badge
[img-slack-badge]:https://img.shields.io/badge/slack-join-red.svg?style=for-the-badge&logo=slack
[img-actions-badge]:https://img.shields.io/github/workflow/status/target/strelka/Daily%20Build?&style=for-the-badge
[img-pr-badge]:https://img.shields.io/badge/PRs-welcome-orange.svg?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c3ZnIGlkPSJzdmcyIiB3aWR0aD0iNjQ1IiBoZWlnaHQ9IjU4NSIgdmVyc2lvbj0iMS4wIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPiA8ZyBpZD0ibGF5ZXIxIj4gIDxwYXRoIGlkPSJwYXRoMjQxNyIgZD0ibTI5Ny4zIDU1MC44N2MtMTMuNzc1LTE1LjQzNi00OC4xNzEtNDUuNTMtNzYuNDM1LTY2Ljg3NC04My43NDQtNjMuMjQyLTk1LjE0Mi03Mi4zOTQtMTI5LjE0LTEwMy43LTYyLjY4NS01Ny43Mi04OS4zMDYtMTE1LjcxLTg5LjIxNC0xOTQuMzQgMC4wNDQ1MTItMzguMzg0IDIuNjYwOC01My4xNzIgMTMuNDEtNzUuNzk3IDE4LjIzNy0zOC4zODYgNDUuMS02Ni45MDkgNzkuNDQ1LTg0LjM1NSAyNC4zMjUtMTIuMzU2IDM2LjMyMy0xNy44NDUgNzYuOTQ0LTE4LjA3IDQyLjQ5My0wLjIzNDgzIDUxLjQzOSA0LjcxOTcgNzYuNDM1IDE4LjQ1MiAzMC40MjUgMTYuNzE0IDYxLjc0IDUyLjQzNiA2OC4yMTMgNzcuODExbDMuOTk4MSAxNS42NzIgOS44NTk2LTIxLjU4NWM1NS43MTYtMTIxLjk3IDIzMy42LTEyMC4xNSAyOTUuNSAzLjAzMTYgMTkuNjM4IDM5LjA3NiAyMS43OTQgMTIyLjUxIDQuMzgwMSAxNjkuNTEtMjIuNzE1IDYxLjMwOS02NS4zOCAxMDguMDUtMTY0LjAxIDE3OS42OC02NC42ODEgNDYuOTc0LTEzNy44OCAxMTguMDUtMTQyLjk4IDEyOC4wMy01LjkxNTUgMTEuNTg4LTAuMjgyMTYgMS44MTU5LTI2LjQwOC0yNy40NjF6IiBmaWxsPSIjZGQ1MDRmIi8%2BIDwvZz48L3N2Zz4%3D
[img-license-badge]:https://img.shields.io/badge/license-apache-ff69b4.svg?style=for-the-badge&logo=apache
[img-docker-badge]:https://img.shields.io/badge/Supports-Docker-lightgrey.svg?style=for-the-badge&logo=docker





