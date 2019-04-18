# Strelka
Strelka is a real-time file scanning system used for threat hunting, threat detection, and incident response. Originally based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at huge scale.

This is a preview branch that brings compatibility breaking changes to Strelka. The most significant changes to the project are:
* System now fully utilizes containers (no anticipated support for direct server installations)
* System uses multiple Redis databases for file caching and task queuing
* ZeroMQ/0MQ is replaced by gRPC
* Support for multiple languages -- Go and Python out-of-the-box
* Authentication, encryption, and load balancing provided by [envoy](https://www.envoyproxy.io/)
* Remote retrieval capabilities are temporarily excluded (but will be brought in via future PRs)

## Quickstart

To begin using the system, ensure that you have [docker](https://docs.docker.com/install/) and [docker-compose](https://docs.docker.com/compose/install/) installed. From the root of the repository, a sample system can be brought up by running the following command: `docker-compose -f build/docker-compose.yaml --project-name strelka up`

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license.
