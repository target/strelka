# Strelka
Strelka is a real-time file scanning system used for threat hunting, threat detection, and incident response. Based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at huge scale.

This is an experimental branch that uses gRPC instead of ZeroMQ for network communication!

## 0MQ --> gRPC

Migrating from ZeroMQ to gRPC brings a number of changes to the project -- before creating an official migration path, here are high-level points to keep in mind if you would like to use this branch.
* There is no more client library -- instead, use `strelka.proto` and the documentation at https://grpc.io/ to create a client in any language that is supported by gRPC
* The server library was consolidated to the file `lib.py`
* `etc/` has been refactored, now all defaults and configs are loaded from memory
* `strelka.py` runs the server
* there is no more 'broker' -- instead, use [Envoy](https://www.envoyproxy.io/)
* encryption is handled by Envoy -- if E2E encryption is needed, run an Envoy mesh
* server options are mostly new and now stored in `server.yaml` with references to other YAML files
* `pylogging.ini` is now `logging.yaml`
* minor changes to distribution settings in `scan.yaml`
* remote retrieval from AWS, GCP, and Swift is untested
* probably lots more?

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license.
