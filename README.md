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

Files in the `build/` and `configs/` directories are designed to start a demo system. The demo system can be brought up by running the following command from the root of the repository:
```
docker-compose -f build/docker-compose.yaml --project-name strelka up
```

Client apps `strelka-fileshot` and `strelka-filestream` are go gettable:
```
go install git.target.com/CFC/strelka/src/go/cmd/strelka-fileshot/
go install git.target.com/CFC/strelka/src/go/cmd/strelka-filestream/
```

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license.
