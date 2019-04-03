# Strelka
Strelka is a real-time file scanning system used for threat hunting, threat detection, and incident response. Based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at huge scale.

This is an experimental branch that uses gRPC instead of ZeroMQ for network communication!

## 0MQ --> gRPC

Migrating from ZeroMQ to gRPC brings a number of changes to the project -- before creating an official migration path, here are high-level points to keep in mind if you would like to use this branch.
* The project is now 'Docker-first' -- there will be "soft support" for non-Docker deployments, but the only recommended deployment model is using Docker (see `docker/`)
* Redis is now a critical part of the system -- the system uses three self-maintaining databases (filekeeper, gatekeeper, and jobkeeper) to coordinate data
    * filekeeper: used to temporarily store file data input into the system
    * gatekeeper: used to serve results for recently scanned files
    * jobkeeper: used to coordinate jobs between the frontend (gRPC servicer) and backend (file processors)
* There is no more client library -- instead, use `strelka.proto` and the documentation at https://grpc.io/ to create a client in any language that is supported by gRPC
* The server library was consolidated to the file `core.py`
* Application scripts were moved to `bin/` and include `strelka-backend` (file processing), `strelka-frontend` (gRPC servicer), and `strelka-mmrpc` (MaliciousMacroBot running as gRPC service, used with ScanMmbot scanner)
* All config files moved to `cfg/`, many options have changed
* There is no more 'broker' or similar central component -- instead, use [Envoy](https://www.envoyproxy.io/)
* Encryption is handled by Envoy -- if E2E encryption is needed, run an Envoy mesh
* `pylogging.ini` is now `logging.yaml`
* minor changes to distribution settings in `scan.yaml`
* remote retrieval from AWS, GCP, and Swift is currently unmerged
* documentation needs an overhaul

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license.
