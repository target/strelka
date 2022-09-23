# Strelka
Strelka is a real-time, container-based file scanning system used for threat hunting, threat detection, and incident response. Originally based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at enterprise scale.

Strelka differs from its sibling projects in a few significant ways:
* Core codebase is Go and Python3.6+
* Server components run in containers for ease and flexibility of deployment
* OS-native client applications for Windows, Mac, and Linux
* Built using [libraries and formats](#architecture) that allow cross-platform, cross-language support

[![Target’s CFC-Open-Source Slack Invitation](https://cfc-slack-inv.herokuapp.com/badge.svg?colorA=155799&colorB=159953)](https://cfc-slack-inv.herokuapp.com/)
* [Target's CFC Slack Room](https://cfc-open-source.slack.com)

## Table of Contents
* [FAQ](#frequently-asked-questions)
* [Installation](#installation)
    * [Client Install](#client-install)
    * [Server Install](#server-install)
* [Quickstart](#quickstart)
* [Deployment](#deployment)
    * [Client Apps](#client-apps)
        * [strelka-fileshot](#strelka-fileshot)
        * [strelka-oneshot](#strelka-oneshot)
        * [strelka-filestream](#strelka-filestream)
        * [strelka-webscrape](#strelka-webscrape)
    * [Server Components](#server-components)
        * [strelka-frontend](#strelka-frontend)
        * [strelka-backend](#strelka-backend)
        * [strelka-manager](#strelka-manager)
        * [coordinator](#coordinator)
        * [gatekeeper](#gatekeeper)
        * [mmrpc](#mmrpc)
    * [Configuration Files](#configuration-files)
        * [fileshot](#fileshot)
        * [filestream](#filestream)
        * [frontend](#frontend)
        * [backend](#backend)
        * [manager](#manager)
    * [Encryption and Authentication](#encryption-and-authentication)
    * [Clusters](#clusters)
        * [Design Patterns](#design-patterns)
        * [General Recommendations](#general-recommendations)
        * [Sizing Considerations](#sizing-considerations)
        * [Container Considerations](#container-considerations)
        * [Management](#management)
* [Architecture](#architecture)
    * [Overview](#overview)
    * [Networking](#networking)
    * [Messaging](#messaging)
    * [Data](#data)
* [Design](#design)
    * [Communication](#communication)
    * [File Distribution, Scanners, Flavors, and Tastes](#file-distribution-scanners-flavors-and-tastes)
    * [Protobuf](#protobuf)
* [Scanners](#scanners)
    * [Scanner List](#scanner-list)
* [Use Cases](#use-cases)
* [Contributing](#contributing)
* [Related Projects](#related-projects)
* [Licensing](#licensing)

## Frequently Asked Questions
### "Who is Strelka?"
[Strelka](https://en.wikipedia.org/wiki/Soviet_space_dogs#Belka_and_Strelka) is one of the second generation Soviet space dogs to achieve orbital spaceflight -- the name is an homage to [Lockheed Martin's Laika BOSS](https://github.com/lmco/laikaboss), one of the first public projects of this type and from which Strelka's core design is based.

### "Why would I want a file scanning system?"
File metadata is an additional pillar of data (alongside network, endpoint, authentication, and cloud) that is effective in enabling threat hunting, threat detection, and incident response and can help event analysts and incident responders bridge visibility gaps in their environment. This type of system is especially useful for identifying threat actors during [KC3 and KC7](https://en.wikipedia.org/wiki/Kill_chain#Computer_security_model). For examples of what Strelka can do, please read the [use cases](#use-cases).

### "Should I switch from my current file scanning system to Strelka?"
It depends -- we recommend reviewing the features of each and choosing the most appropriate tool for your needs. We believe the most significant motivating factors for switching to Strelka are:
* More scanners (40+ at release) and file types (60+ at release) than [related projects](#related-projects)
* Modern codebase (Go and Python3.6+)
* Server components run in containers for ease and flexibility of deployment
* Performant, OS-native client applications compatible with Windows, Mac, and Linux
* OS-native client applications for Windows, Mac, and Linux
* Built using [libraries and formats](#architecture) that allow cross-platform, cross-language support

### "Are Strelka's scanners compatible with Laika BOSS, File Scanning Framework, or Assemblyline?"
Due to differences in design, Strelka's scanners are not directly compatible with Laika BOSS, File Scanning Framework, or Assemblyline. With some effort, most scanners can likely be ported to the other projects.

### "Is Strelka an intrusion detection system (IDS)?"
Strelka shouldn't be thought of as an IDS, but it can be used for threat detection through YARA rule matching and downstream metadata interpretation. Strelka's design follows the philosophy established by other popular metadata collection systems (Bro, Sysmon, Volatility, etc.): it extracts data and leaves the decision-making up to the user.

### "Does it work at scale?"
Everyone has their own definition of "at scale," but we have been using Strelka and systems like it to scan up to 250 million files each day for over a year and have never reached a point where the system could not scale to our needs -- as file volume and diversity increases, horizontally scaling the system should allow you to scan any number of files.

### "Doesn't this use a lot of bandwidth?"
Maybe! Strelka's client applications provide opportunities for users to use as much or as little bandwidth as they want.

### "Should I run my Strelka cluster on my Bro/Suricata network sensor?"
No! Strelka clusters run CPU-intensive processes that will negatively impact system-critical applications like Bro and Suricata. If you want to integrate a network sensor with Strelka, then use the [`filestream`] client application. This utility is capable of sending millions of files per day from a single network sensor to a Strelka cluster without impacting system-critical applications.

### "I have other questions!"
Please file an issue or contact the project team at [TTS-CFC-OpenSource@target.com](mailto:TTS-CFC-OpenSource@target.com).

## Installation
Strelka can be installed on any system that can run [containers](https://www.docker.com/resources/what-container). For convenience, the project ships with [docker-compse](https://docs.docker.com/compose/) configuration files for standing up a "quickstart" cluster (found under the `build/` directory). We do not recommend using and do not plan to support OS-native installations.

### Client Install
Strelka's core client apps are written in Go and can be run natively on a host or inside of a container. The following are multiple ways to install each of the apps.

#### strelka-fileshot (build)
1. Build the binary directly from github
    ```sh
    go build github.com/target/strelka/src/go/cmd/strelka-fileshot
    ```

#### strelka-fileshot (build)
1. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

2. Build the application
    ```sh
    cd /opt/strelka/src/go/cmd/strelka-fileshot/
    go build -o strelka-fileshot .
    ```

#### strelka-fileshot (container)
1. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

2. Build the container
    ```sh
    cd /opt/strelka/
    docker build -f build/go/fileshot/Dockerfile -t strelka-fileshot .
    ```

#### strelka-oneshot (Build the binary directly from github)
1. Build the binary
    ```sh
    go build github.com/target/strelka/src/go/cmd/strelka-oneshot
    ```

#### strelka-oneshot (build)
1. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

2. Build the application
    ```sh
    cd /opt/strelka/src/go/cmd/strelka-oneshot/
    go build -o strelka-oneshot .
    ```
   
#### strelka-oneshot (container)
1. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

2. Build the container
    ```sh
    cd /opt/strelka/
    docker build -f build/go/oneshot/Dockerfile -t strelka-oneshot .
    ```
   
#### strelka-filestream (Build the binary directly from github)
1. Build the binary
    ```sh
    go build github.com/target/strelka/src/go/cmd/strelka-filestream
    ```

#### strelka-filestream (build)
1. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

2. Build the application
    ```sh
    cd /opt/strelka/src/go/cmd/strelka-filestream/
    go build -o strelka-filestream .
    ```

#### strelka-filestream (container)
1. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

2. Build the container
    ```sh
    cd /opt/strelka/
    docker build -f build/go/filestream/Dockerfile -t strelka-filestream .
    ```

### Server Install
Strelka's core server components are written in Go and Python3.6 and are run from containers. The simplest way to run them is to use docker-compose -- see `build/docker-compose.yaml` for a sample configuration.

#### Docker
1. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

2. Build the cluster
    ```sh
    cd /opt/strelka/
    docker-compose -f build/docker-compose.yaml up -d
    ```

## Quickstart
By default, Strelka is configured to use a minimal "quickstart" deployment that allows users to test the system. This configuration **is not recommended** for production deployments, but may suffice for environments with very low file volume (<50k files per day). Using two Terminal windows, do the following:

Terminal 1
```
$ docker-compose -f build/docker-compose.yaml up
```

Terminal 2:
```
$ strelka-fileshot -c fileshot.yaml
$ cat strelka.log | jq .
```

Terminal 1 runs a full Strelka cluster with logs printed to stdout and Terminal 2 is used to send files to the cluster. `fileshot.yaml` will need the `patterns` field updated to identify files to scan, by default scan results will be written to `./strelka.log`.

## Deployment
### Client Apps
Strelka's core client apps are designed to efficiently integrate a wide-range of systems (Windows, Mac, Linux) with a cluster. Out of the box client apps are written in Go and custom clients can be written in any language supported by gRPC.

#### strelka-fileshot
This client app is designed to one-shot upload files and retrieve their results. This app can be applied in many scenarios, including on-demand file scanning from analysts triaging malware, scheduled file scanning on remote systems, and one-time file scanning on during incident response.

#### strelka-oneshot
This client app is designed to be used to submit a single file from command line and receive the result for it immediately.
This is useful if you want to test the functionality of Strelka without having to write a config file (like with strelka-fileshot).

An example execution could look like:

```bash
$ strelka-oneshot -f foo.exe
$ cat strelka-oneshot.log | jq .
```

#### strelka-filestream
This client app is designed to continuously stream files and retrieves their results. This app is intended for use on systems that continuously generate files, such as network security monitoring (NSM) sensors, email gateways, and web proxies. Note that this client application *moves files on the filesystem* before sending files for scanning.

#### strelka-webscrape (TODO)
This client app is designed to recursively scrape websites, upload their contents, and retrieve the results. This app is intended for monitoring websites for third party compromise or malicious code injection.

### Server Components
#### strelka-frontend
This server component is the frontend for a cluster -- clients can connect directly a single frontend or to many frontends via [Envoy](https://www.envoyproxy.io/).

#### strelka-backend
This server component is the backend for a cluster -- this is where files submitted to the cluster are processed.

#### strelka-manager
This server component manages portions of Strelka's Redis databases.

#### coordinator
This server component is a Redis server that coordinates tasks and data between the frontend and backend. This component is compatible with Envoy's Redis load balancing capabilities.

#### gatekeeper
This server component is a Redis server that acts as a temporary event cache. This component is not compatible with Envoy's Redis load balancing capabilities.

#### mmrpc
This is an optional server component that turns the [MaliciousMacroBot](https://github.com/egaus/MaliciousMacroBot) project into a networked service with gRPC.

### Configuration Files
Strelka uses YAML for configuring client and server components. We recommend using the default configurations and modifying the options as needed.

#### fileshot
For the options below, only one response setting may be configured.

* "conn.server": network address of the frontend server (defaults to 127.0.0.1:57314)
* "conn.cert": local path to the frontend SSL server certificate (defaults to empty string -- SSL disabled)
* "conn.timeout.dial": amount of time to wait for the client to dial the server (defaults to 5 seconds)
* "conn.timeout.file": amount of time to wait for an individual file to complete a scan (defaults to 1 minute)
* "conn.concurrency": number of concurrent requests to make (defaults to 8)
* "files.chunk": size of file chunks that will be sent to the frontend server (defaults to 32768b / 32kb)
* "files.patterns": list of glob patterns that determine which files will be sent for scanning (defaults to example glob pattern)
* "files.delay": artificial sleep between the submission of each chunk
* "files.delete": boolean that determines if files should be deleted after being sent for scanning (defaults to false -- does not delete files)
* "files.gatekeeper": boolean that determines if events should be pulled from the temporary event cache (defaults to true)
* "response.log": location where worker scan results are logged to (defaults to /var/log/strelka/strelka.log)
* "response.report": frequency at which the frontend reports the number of files processed (no default)

#### filestream
For the options below, only one response setting may be configured.

* "conn.server": network address of the frontend server (defaults to 127.0.0.1:57314)
* "conn.cert": local path to the frontend SSL server certificate (defaults to empty string -- SSL disabled)
* "conn.timeout.dial": amount of time to wait for the client to dial the server (defaults to 5 seconds)
* "conn.timeout.file": amount of time to wait for an individual file to complete a scan (defaults to 1 minute)
* "conn.concurrency": number of concurrent requests to make (defaults to 8)
* "files.chunk": size of file chunks that will be sent to the frontend server (defaults to 32768b / 32kb)
* "files.patterns": list of glob patterns that determine which files will be sent for scanning (defaults to example glob pattern)
* "files.delete": boolean that determines if files should be deleted after being sent for scanning (defaults to false -- does not delete files)
* "files.processed": directory where files will be moved after being submitted for scanning (defaults to "", and files stay in staging directory)
* "response.log": location where worker scan results are logged to (defaults to /var/log/strelka/strelka.log)
* "response.report": frequency at which the frontend reports the number of files processed (no default)
* "delta": time value that determines how much time must pass since a file was last modified before it is sent for scanning (defaults to 5 seconds)
* "staging": directory where files are staged before being sent to the cluster (defaults to example path)

#### frontend
For the options below, only one response setting may be configured.

* "server": network address of the frontend server (defaults to :57314)
* "coordinator.addr": network address of the coordinator (defaults to strelka_coordinator_1:6379)
* "coordinator.db": Redis database of the coordinator (defaults to 0)
* "gatekeeper.addr": network address of the gatekeeper (defaults to strelka_gatekeeper_1:6379)
* "gatekeeper.db": Redis database of the gatekeeper (defaults to 0)
* "gatekeeper.ttl": time-to-live for events added to the gatekeeper (defaults to 1 hour)
* "response.log": location where worker scan results are logged to (defaults to /var/log/strelka/strelka.log)
* "response.report": frequency at which the frontend reports the number of files processed (no default)

#### manager
* "coordinator.addr": network address of the coordinator (defaults to strelka_coordinator_1:6379)
* "coordinator.db": Redis database of the coordinator (defaults to 0)

#### backend
The backend configuration contains two sections: one that controls the backend process and one that controls how scanners are applied to data.

* "logging_cfg": path to the Python logging configuration (defaults to /etc/strelka/logging.yaml)
* "limits.max_files": number of files the backend will process before shutting down (defaults to 5000, specify 0 to disable)
* "limits.time_to_live": amount of time (in seconds) that the backend will run before shutting down (defaults to 900 seconds / 15 minutes, specify 0 to disable)
* "limits.max_depth": maximum depth that extracted files will be processed by the backend (defaults to 15)
* "limits.distribution": amount of time (in seconds) that a single file can be distributed to all scanners (defaults to 600 seconds / 10 minutes)
* "limits.scanner": amount of time (in seconds) that a scanner can spend scanning a file (defaults to 150 seconds / 1.5 minutes, can be overridden per-scanner)
* "coordinator.addr": network address of the coordinator (defaults to strelka_coordinator_1:6379)
* "coordinator.db": Redis database of the coordinator (defaults to 0)
* "tasting.mime_db": location of the MIME database used to taste files (defaults to None, system default)
* "tasting.yara_rules": location of the directory of YARA files that contains rules used to taste files (defaults to /etc/strelka/taste/)

##### scanners
The "scanners" section controls which scanners are assigned to each file; each scanner is assigned by mapping flavors, filenames, and sources from this configuration to the file. "scanners" must always be a dictionary where the key is the scanner name (e.g. `ScanZip`) and the value is a list of dictionaries containing values for mappings, scanner priority, and scanner options.

Assignment occurs through a system of positive and negative matches: any negative match causes the scanner to skip assignment and at least one positive match causes the scanner to be assigned. A unique identifier (`*`) is used to assign scanners to all flavors. See [File Distribution, Scanners, Flavors, and Tasting](#file-distribution-scanners-flavors-and-tastes) for more details on flavors.

Below is a sample configuration that runs the scanner "ScanHeader" on all files and the scanner "ScanRar" on files that match a YARA rule named "rar_file".
```yaml
scanners:
  'ScanHeader':
    - positive:
        flavors:
          - '*'
      priority: 5
      options:
        length: 50
  'ScanRar':
    - positive:
        flavors:
          - 'rar_file'
      priority: 5
      options:
        limit: 1000
```

The "positive" dictionary determines which flavors, filenames, and sources cause the scanner to be assigned. Flavors is a list of literal strings while filenames and sources are regular expressions. One positive match will assign the scanner to the file.

Below is a sample configuration that shows how RAR files can be matched against a YARA rule (`rar_file`), a MIME type (`application/x-rar`), and a filename (any that end with `.rar`).
```yaml
scanners:
  'ScanRar':
    - positive:
        flavors:
          - 'application/x-rar'
          - 'rar_file'
        filename: '\.rar$'
      priority: 5
      options:
        limit: 1000
```

Each scanner also supports negative matching through the "negative" dictionary. Negative matches occur before positive matches, so any negative match guarantees that the scanner will not be assigned. Similar to positive matches, negative matches support flavors, filenames, and sources.

Below is a sample configuration that shows how RAR files can be positively matched against a YARA rule (`rar_file`) and a MIME type (`application/x-rar`), but only if they are not negatively matched against a filename (`\.rar$`). This configuration would cause `ScanRar` to only be assigned to RAR files that do not have the extension ".rar".
```yaml
scanners:
  'ScanRar':
    - negative:
        filename: '\.rar$'
      positive:
        flavors:
          - 'application/x-rar'
          - 'rar_file'
      priority: 5
      options:
        limit: 1000
```

Each scanner supports multiple mappings -- this makes it possible to assign different priorities and options to the scanner based on the mapping variables. If a scanner has multiple mappings that match a file, then the first mapping wins.

Below is a sample configuration that shows how a single scanner can apply different options depending on the mapping.
```yaml
scanners:
  'ScanX509':
    - positive:
        flavors:
          - 'x509_der_file'
      priority: 5
      options:
        type: 'der'
    - positive:
        flavors:
          - 'x509_pem_file'
      priority: 5
      options:
        type: 'pem'
```

### Encryption and Authentication
Strelka's client apps and server components support encryption and authentication (EA) via Envoy.

#### Envoy
Envoy is a highly regarded, open source proxy created by Lyft and used by many large organizations. One Envoy proxy can provide EA between clients and frontends while many Envoy proxies can provide end-to-end EA. This repository contains two Envoy proxy configurations to help users get started, both are found in `misc/envoy/*`.

#### Certstrap
If users do not have an SSL certificate managing system, then we recommend using [certstrap](https://github.com/square/certstrap), an open source certificate manager created by Square.

### Clusters
The following are recommendations and considerations to keep in mind when deploying clusters.

#### Design Patterns
Strelka's container-based design allows for significant flexibility in designing a distributed system that works for your environment. Below are some recommended design patterns.

##### Quickstart
The quickstart pattern is intended for demonstration and integration testing. With this pattern, all server components run on a single host. Not intended for clusters scanning more than 10k files per day or large bursts of files.

##### Short Stack
The short stack pattern is intended for small-to-medium environments. With this pattern, server components are distributed onto at least three hosts -- one running a frontend, one running Redis databases, and one or more running backends. Horizontally scaling backends allows users to scan many more files per day and handle large bursts of file activity.

##### Tall Stack
The tall stack pattern is intended for large-to-huuuuuuge environments. With this pattern, server components are fully distributed across many hosts -- one running two instances of Envoy, multiple running frontends, multiple running backends, and multiple running Redis databases. Horizontally scaling frontends, backends, and Redis databases allows you to handle any volume of files you want.

#### General Recommendations
The following recommendations apply to all clusters:
* Do not over-allocate backend CPUs
    * .75 backend per CPU is recommended
        * On a server with 4 CPUs, 3 are used by backends
        * On a server with 8 CPUs, 6 are used by backends
* Allocate at least 1GB RAM per backend
    * If backends do not have enough RAM, then there will be excessive memory errors
    * Big files (especially compressed files) require more RAM
* Allocate as much RAM as reasonable to the coordinator(s)

#### Sizing Considerations
Multiple variables should be considered when determining the appropriate size for a cluster:
* Number of file requests per second
* Diversity of files requested
    * Binary files take longer to scan than text files
* Number of YARA rules deployed
    * Scanning a file with 50,000 rules takes longer than scanning a file with 50 rules

The best way to properly size a cluster is to start small, measure performance, and scale out as needed.

#### Container Considerations
Below is a list of container-related considerations to keep in mind when running a cluster:
* Share volumes (not files) with the container
    * Strelka's backend will read configuration files and YARA rules files when they startup -- sharing volumes with the container ensures that updated copies of these files on the localhost are reflected accurately inside the container without needing to restart the container
* [Increase shm-size](https://docs.docker.com/engine/reference/commandline/run/#options)
    * By default, Docker limits a container's shm size to 64MB -- this can cause errors with Strelka scanners that utilize `tempfile`
* [Set logging options](https://docs.docker.com/config/containers/logging/configure/#supported-logging-drivers)
    * By default, Docker has no log limit for logs output by a container

#### Management
Due to its distributed design, we recommend using container orchestration (e.g. Kubernetes) or configuration management/provisioning (e.g. Ansible, SaltStack, etc.) systems for managing clusters.

## Architecture
### Overview
Strelka's architecture allows clients ("client(s)") to submit files to one or many intake servers ("frontend(s)") which coordinate requests with caching (Redis) and processing servers ("backend(s)"). In combination, all server components create a "cluster." During file processing, files are sent through a series of data and file extraction modules ("scanners") via a user-defined distribution system ("tastes" and "flavors"); file scan results are sent back to the client and can be intercepted by the frontend, from which they can be sent to downstream analytics platforms (e.g. ElasticStack, Splunk, etc.).

This architecture makes the following deployments possible:
* 1-to-1 cluster (one client to one backend)
* 1-to-N cluster (one client to N backends)
* N-to-1 cluster (N clients to one backend)
* N-to-N cluster (N clients to N backends)

The most practical deployment is an N-to-N cluster -- this creates a fully scalable deployment that can be modified in-place without requiring significant cluster downtime.

### Networking
Clients and frontends communicate using gRPC, frontends and backends communicate using Redis.

### Messaging
gRPC uses [protocol buffers](https://developers.google.com/protocol-buffers/) (protobuf) as its messaging format. File requests are converted into gRPC-valid protobuf (defined in `src/go/api/strelka/` and `src/python/strelka/proto/`) and represent a strict contract for how clients should communicate with a cluster. New clients can be written in [any language supported by gRPC](https://grpc.io/faq/).

### Data
Configuration files are written in YAML format. Events are output as JSON using snakecase-formatted fields. Timestamp metadata follows [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) when appropriate.

## Design
### Communication
Communication occurs through a combination of gRPC and Redis.

#### Client-to-Frontend
Client-to-frontend communication uses bi-directional gRPC streams. Clients upload their requests in chunks and receive scan results one-by-one for their request. If a file request is successful, then clients will always receive scan results for their requests and can choose how to handle these results.

#### Frontend-to-Backend
Frontend-to-backend communication uses one or many Redis server, referred to as the 'coordinator' or 'coordinators'.

The coordinator acts as a task queue between the frontend and backend, a temporary file cache for the backend, and the database where the backend sends scan results for the frontend to pick up and send to the client. The coordinator can be scaled horizontally via Envoy's Redis proxy.

### Frontend-to-Gatekeeper
Frontend-to-gatekeeper communication relies on one Redis server, referred to as the 'gatekeeper'.

The gatekeeper is a temporary event cache from which the frontend can optionally retrieve events. As file chunks stream into the frontend, they are hashed with SHA256 and, when the file is complete, the frontend checks the gatekeeper to see if it has any events related to the requested file. If events exist and the client has not set the option to bypass the gatekeeper, then the cached file events are sent back to the client.

### File Distribution, Scanners, Flavors, and Tastes
Strelka's file distribution assigns scanners (`src/python/strelka/scanners/`) to files based on a system of "flavors" and "tastes". Flavors describe the type of file being distributed through the system and come in three types:
* MIME flavors -- assigned by libmagic (e.g. "application/zip")
* YARA flavors -- assigned by YARA rule matches (e.g. "zip_file")
* External flavors -- assigned by a parent file (e.g. "zip")

As files enter the system, they are tasted (e.g. scanned with YARA), their flavor is identified, and the flavor is checked for a corresponding mapping in the scanners configuration (`configs/python/backend/backend.yaml`, see [scanners](#scanners) for more details) -- flavors are the primary method through which scanners are assigned to files.

### protobuf
#### `ScanFileRequest` protobuf
Below is a description of the keys included in the `ScanFileRequest` protobuf. All keys are optional unless otherwise specified as required. This protobuf can be used to create new client apps in other programming languages supported by gRPC.
* "bytes": file data (required)
* "request.id": string used to identify the request
* "request.client": string used to identify the Strelka client app
* "request.source": string used to identify the system or source of the request
* "attributes.filename": string containing the name of the file in the request
* "attributes.metadata": map of strings that contains metadata associated with the request

#### `ScanHttpRequest` protobuf (unimplemented)
Below is a description of the keys included in the `ScanHttpRequest` protobuf. All keys are optional unless otherwise specified as required. This protobuf can be used to create new client apps in other programming languages supported by gRPC.
* "url": url from which file data will be retrieved (required)
* "request.id": string used to identify the request
* "request.client": string used to identify the Strelka client app
* "request.source": string used to identify the system or source of the request
* "attributes.filename": string containing the name of the file in the request
* "attributes.metadata": map of strings that contains metadata associated with the request

## Scanners
Each scanner parses files of a specific flavor and performs data collection and/or file extraction on them. Scanners are typically named after the type of file they are intended to scan (e.g. "ScanHtml", "ScanPe", "ScanRar") but may also be named after the type of function or tool they use to perform their tasks (e.g. "ScanExiftool", "ScanHeader", "ScanOcr").

### Scanner List
The table below describes each scanner and its options. Each scanner has the hidden option "scanner_timeout" which can override the distribution scanner_timeout.

| Scanner Name      | Scanner Description                                                                    | Scanner Options                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Contributor |
|-------------------|----------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| ScanAntiword      | Extracts text from MS Word documents                                                   | "tempfile_directory" -- location where tempfile writes temporary files (defaults to "/tmp/")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ScanBatch         | Collects metadata from batch script files                                              | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanBase64        | Decodes base64-encoded files                                                           | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | [Nathan Icart](https://github.com/nateicart)
| ScanBITS          | Analyzes Windows BITS scheduler database files                                         | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanBzip2         | Decompresses bzip2 files                                                               | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanCapa          | Analyzes executable files with FireEye [capa](https://github.com/fireeye/capa)         | "tempfile_directory" -- location where `tempfile` will write temporary files (defaults to "/tmp/")<br>"location" -- location of the capa rules file or directory (defaults to "/etc/capa/")                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ScanCuckoo        | Sends files to a Cuckoo sandbox                                                        | "url" -- URL of the Cuckoo sandbox (defaults to None)<br>"priority" -- Cuckoo priority assigned to the task (defaults to 3)<br>"timeout" -- amount of time (in seconds) to wait for the task to upload (defaults to 10)<br>"unique" -- boolean that tells Cuckoo to only analyze samples that have not been analyzed before (defaults to True)<br>"username" -- username used for authenticating to Cuckoo (defaults to None, optionally read from environment variable "CUCKOO_USERNAME")<br>"password" -- password used for authenticating to Cuckoo (defaults to None, optionally read from environment variable "CUCKOO_PASSWORD")                                |
| ScanDocx          | Collects metadata and extracts text from docx files                                    | "extract_text" -- boolean that determines if document text should be extracted as a child file (defaults to False)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ScanElf           | Collects metadata from ELF files                                                       | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanEmail         | Collects metadata and extract files from email messages                                | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanEncryptedDoc  | Attempts to extract decrypted Office documents through brute force password cracking   | "password_file" -- location of passwords file for encrypted documents (defaults to etc/strelka/passwords.txt)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ScanEntropy       | Calculates entropy of files                                                            | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanExiftool      | Collects metadata parsed by Exiftool                                                   | "tempfile_directory" -- location where tempfile writes temporary files (defaults to "/tmp/")<br>"keys" -- list of keys to log (defaults to all)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ScanFalconSandbox | Sends files to an instance of Falcon Sandbox                                           | "server" -- URL of the Falcon Sandbox API inteface <br>"priority" -- Falcon Sandbox priority assigned to the task (defaults to 3)<br>"timeout" -- amount of time (in seconds) to wait for the task to upload (defaults to 60)<br>"envID" -- list of numeric envrionment IDs that tells Falcon Sandbox which sandbox to submit a sample to (defaults to [100])<br>"api_key" -- API key used for authenticating to Falcon Sandbox (defaults to None, optionally read from environment variable "FS_API_KEY")<br>"api_secret" --  API secret key used for authenticating to Falcon Sandbox (defaults to None, optionally read from environment variable "FS_API_SECKEY") |
| ScanFloss         | Analyzes executable files with FireEye [floss](https://github.com/fireeye/flare-floss) | "tempfile_directory" -- location where `tempfile` will write temporary files (defaults to "/tmp/")<br>"limit" -- Maximum amount of strings to collect. (defaults to 100)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ScanGif           | Extracts data embedded in GIF files                                                    | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanGzip          | Decompresses gzip files                                                                | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
| ScanHash          | Calculates file hash values                                                            | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanHeader        | Collects file header                                                                   | "length" -- number of header characters to log as metadata (defaults to 50)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ScanHtml          | Collects metadata and extracts embedded files from HTML files                          | "parser" -- sets the HTML parser used during scanning (defaults to "html.parser")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ScanIni           | Parses keys from INI files                                                             | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanIso           | Collects and extracts files from ISO files                                             | "limit" -- maximum number of files to extract (defaults to 0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ScanJarManifest   | Collects metadata from JAR manifest files                                              | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanJavascript    | Collects metadata from Javascript files                                                | "beautify" -- beautifies JavaScript before parsing (defaults to True)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ScanJpeg          | Extracts data embedded in JPEG files                                                   | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanJson          | Collects keys from JSON files                                                          | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanLibarchive    | Extracts files from libarchive-compatible archives.                                    | "limit" -- maximum number of files to extract (defaults to 1000)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ScanLnk           | Collects metadata from lnk files.                                                      | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Ryan Borre, [DerekT2](https://github.com/Derekt2), [Nathan Icart](https://github.com/nateicart)
| ScanLzma          | Decompresses lzma files                                                                | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanMacho         | Collects metadata from Mach-O files                                                    | "tempfile_directory" -- location where tempfile writes temporary files (defaults to "/tmp/")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ScanManifest      | Collects metadata from Chrome Manifest files                                           | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | [DerekT2](https://github.com/Derekt2)
| ScanMmbot         | Collects VB results from a server running mmbotd                                       | "server" -- network address and network port of the mmbotd server (defaults to "127.0.0.1:33907")<br>"timeout" -- amount of time (in milliseconds) to wait for a response from the server (defaults to 10000)                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ScanOcr           | Collects metadata and extracts optical text from image files                           | "extract_text" -- boolean that determines if document text should be extracted as a child file (defaults to False)<br>"tempfile_directory" -- location where `tempfile` will write temporary files (defaults to "/tmp/")                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ScanOle           | Extracts files from OLECF files                                                        | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanPdf           | Collects metadata and extracts streams from PDF files                                  | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanPe            | Collects metadata from PE files                                                        | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanPgp           | Collects metadata from PGP files                                                       | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanPhp           | Collects metadata from PHP files                                                       | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanPkcs7         | Extracts files from PKCS7 certificate files                                            | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanPlist         | Collects attributes from binary and XML property list files                            | "keys" -- list of keys to log (defaults to all)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ScanQr            | Collects QR code metadata from image files                                             | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | [Aaron Herman](https://github.com/aaronherman)
| ScanRar           | Extracts files from RAR archives                                                       | "limit" -- maximum number of files to extract (defaults to 1000)<br>"password_file" -- location of passwords file for RAR archives (defaults to etc/strelka/passwords.txt)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ScanRpm           | Collects metadata and extracts files from RPM files                                    | "tempfile_directory" -- location where `tempfile` will write temporary files (defaults to "/tmp/")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ScanRtf           | Extracts embedded files from RTF files                                                 | "limit" -- maximum number of files to extract (defaults to 1000)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ScanStrings       | Collects strings from file data                                                        | "limit" -- maximum number of strings to collect, starting from the beginning of the file (defaults to 0, collects all strings)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ScanSwf           | Decompresses swf (Flash) files                                                         | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanTar           | Extract files from tar archives                                                        | "limit" -- maximum number of files to extract (defaults to 1000)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ScanTnef          | Collects metadata and extract files from TNEF files                                    | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanUpx           | Decompresses UPX packed files                                                          | "tempfile_directory" -- location where `tempfile` will write temporary files (defaults to "/tmp/")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ScanUrl           | Collects URLs from files                                                               | "regex" -- dictionary entry that establishes the regular expression pattern used for URL parsing (defaults to a widely scoped regex)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ScanVb            | Collects metadata from Visual Basic script files                                       | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ScanVba           | Extracts and analyzes VBA from document files                                          | "analyze_macros" -- boolean that determines if macros should be analyzed (defaults to True)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ScanX509          | Collects metadata from x509 and CRL files                                              | "type" -- string that determines the type of x509 certificate being scanned (no default, assigned as either "der" or "pem" depending on flavor)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ScanXL4MA         | Analyzes and parses Excel 4 Macros from XLSX files                                     | "type" -- string that determines the type of x509 certificate being scanned (no default, assigned as either "der" or "pem" depending on flavor)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Ryan Borre
| ScanXml           | Log metadata and extract files from XML files                                          | "extract_tags" -- list of XML tags that will have their text extracted as child files (defaults to empty list)<br>"metadata_tags" -- list of XML tags that will have their text logged as metadata (defaults to empty list)                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ScanYara          | Scans files with YARA rules                                                            | "location" -- location of the YARA rules file or directory (defaults to "/etc/yara/")<br>"metadata_identifiers" -- list of YARA rule metadata identifiers (e.g. "Author") that should be logged as metadata (defaults to empty list)                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ScanZip           | Extracts files from zip archives                                                       | "limit" -- maximum number of files to extract (defaults to 1000)<br>"password_file" -- location of passwords file for zip archives (defaults to etc/strelka/passwords.txt)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ScanZlib          | Decompresses gzip files                                                                | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   

## Use Cases
Below are some select use cases that show the value Strelka can add to a threat detection tech stack. Keep in mind that these results are parsed in real time without post-processing and are typically correlated with other detection/response tools (e.g. Bro, Volatility, etc.). The file metadata shown below was derived from files found in [VirusShare](https://virusshare.com/) torrent no. 323 and from a test file in the [MaliciousMacroBot (MMBot) repository](https://github.com/egaus/MaliciousMacroBot).

### Extracting nested files
Strelka scanners can decompress and unarchive child files from a wide variety of common file formats, including gzip, ISO, RAR, tar, and ZIP. Child files can also be extracted from files that are not typically thought of as file containers, including MZ, HTML, and XML. Child files are recursively scanned by the system and retain their relationship to parent files via unique identifiers (`tree.node`, `tree.parent`, and `tree.root`).

Below is a partial scan result for a ZIP file that contains DLLs, MZ, and text files -- this shows which scanner extracted the child files and the order in which Strelka extracted them.
```json
"VirusShare_f87a71c7cda125599756a7440eac869d"
"ImeHook.dll"
"digital_signature"
"sn_161681096793302212950385451611660389869"
"sn_95367435335131489231313444090147582372"
"sn_35937092757358589497111621496656664184"
"sn_458292208492782643314715"
"sn_43358040091624116037328344820021165185"
"sn_109001353806506068745144901449045193671"
"ImeHook.ime"
"digital_signature"
"sn_161681096793302212950385451611660389869"
"sn_95367435335131489231313444090147582372"
"sn_35937092757358589497111621496656664184"
"sn_43358040091624116037328344820021165185"
"sn_109001353806506068745144901449045193671"
"ImeLoadDll.dll"
"digital_signature"
"sn_161681096793302212950385451611660389869"
"sn_95367435335131489231313444090147582372"
"sn_35937092757358589497111621496656664184"
"sn_458292208492782643314715"
"sn_43358040091624116037328344820021165185"
"sn_109001353806506068745144901449045193671"
"QQXW_sync.dll"
"digital_signature"
"sn_161681096793302212950385451611660389869"
"sn_95367435335131489231313444090147582372"
"sn_35937092757358589497111621496656664184"
"sn_43358040091624116037328344820021165185"
"sn_109001353806506068745144901449045193671"
"QQXuanWUSyncTool.exe"
"Sync.ini"
"_QQXuanWUSyncTool.exe"
"digital_signature"
"sn_161681096793302212950385451611660389869"
"sn_95367435335131489231313444090147582372"
"sn_35937092757358589497111621496656664184"
"sn_43358040091624116037328344820021165185"
"sn_109001353806506068745144901449045193671"
"bbxcomm.dll"
"digital_signature"
"sn_161681096793302212950385451611660389869"
"sn_95367435335131489231313444090147582372"
"sn_35937092757358589497111621496656664184"
"sn_43358040091624116037328344820021165185"
"sn_109001353806506068745144901449045193671"
"msvcr90.dll"
"digital_signature"
"sn_3914548144742538765706922673626944"
"sn_3914548144742538765706922673626944"
"sn_220384538441259235003328"
"sn_458354918584318987075587"
"sn_458441701260288556269574"
"sn_458441701260288556269574"
"sn_140958392345760462733112971764596107170"
"ver.ini"
"╣ñ╛▀╜Θ╔▄.txt"
```

### Identifying malicious scripts
Strelka supports scanning some of the most common types of malicious script files (JavaScript, VBScript, etc.). Not only are these scripts parsed, but they are also extracted out of relevant parent files -- for example, JavaScript and VBScript can be extracted out of HTML files and VBA code can be extracted out of OLE files.

Below is a partial scan result for an HTML file that contains a malicious VBScript file that contains an encoded Windows executable file. HTML hyperlinks are redacted to prevent accidental navigation.
```json
{
  "file": {
    "filename": "VirusShare_af8188122b7580b8907c76352d565616",
    "depth": 0,
    "flavors": {
      "yara": [
        "html_file"
      ],
      "mime": [
        "text/html"
      ]
    },
    "scanner_list": [
      "ScanYara",
      "ScanHash",
      "ScanEntropy",
      "ScanHeader",
      "ScanHtml"
    ],
    "size": 472513
  },
  "tree": {
    "node": "7b9b9460-7943-4f9b-b7e0-c48653a1adbd",
    "root": "7b9b9460-7943-4f9b-b7e0-c48653a1adbd",
  },
  "hash": {
    "md5": "af8188122b7580b8907c76352d565616",
    "sha1": "2a9eef195a911c966c4130223a64f7f47d6f8b8f",
    "sha256": "5f0eb1981ed21ad22f67014b8c78ca1f164dfbc27d6bfe66d49c70644202321e",
    "ssdeep": "6144:SCsMYod+X3oI+YUsMYod+X3oI+YlsMYod+X3oI+YLsMYod+X3oI+YQ:P5d+X3o5d+X3j5d+X315d+X3+"
  },
  "entropy": {
    "entropy": 4.335250015702422
  },
  "header": {
    "header": "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Trans"
  },
  "html": {
    "total": {
      "scripts": 10,
      "forms": 1,
      "inputs": 1,
      "frames": 0,
      "extracted": 7,
      "spans": 11
    },
    "title": "目前学生信息已获0条得1-益民基金",
    "hyperlinks": [
      "http://[redacted].cn/",
      "http://[redacted].cn/list/8031/",
      "http://[redacted].cn/newslist/9021/",
      "http://[redacted].cn/newslist/9075/",
      "http://[redacted].cn/list/2013/",
      "http://[redacted].cn/list/6069/",
      "http://[redacted].cn/list/5082/",
      "http://[redacted].cn/list/7033/",
      "http://[redacted].cn/newslist/1019/",
      "http://[redacted].cn/newslist/8032/",
      "http://[redacted].cn/newslist/2091/",
      "http://[redacted].cn/list/8041/",
      "http://[redacted].cn/template/news/xbwseo02/static/image/magic/doodle.small.gif",
      "http://[redacted].cn/html/20180610/7201976.html",
      "http://[redacted].cn/show/20127883.html",
      "http://[redacted].cn/news/81420152.html",
      "http://[redacted].cn/show/20123664.html",
      "http://[redacted].cn/html/20180610/4201618.html",
      "http://[redacted].cn/html/20180610/9201711.html",
      "http://[redacted].cn/html/20180610/2201468.html",
      "http://[redacted].cn/show/20179372.html",
      "http://[redacted].cn/html/20180610/1201138.html",
      "http://[redacted].cn/news/43120163.html",
      "http://[redacted].cn/html/20180610/6201493.html",
      "http://[redacted].cn/show/20112973.html",
      "http://[redacted].cn/html/20180610/3201566.html",
      "http://[redacted].cn/show/20181646.html",
      "http://[redacted].cn/html/20180610/4201913.html",
      "http://[redacted].cn/news/94820125.html",
      "http://[redacted].cn/show/20111299.html",
      "http://[redacted].cn/news/18920193.html",
      "http://[redacted].com/k2.asp",
      "http://[redacted].cn",
      "http://[redacted].com/index.php",
      "http://[redacted].com",
      "http://[redacted].com/k1.php",
      "http://[redacted].com/k.asp",
      "http://[redacted].com",
      "http://[redacted].org/connect.php",
      "http://[redacted].com/k5.asp",
      "http://[redacted].com/k1.asp",
      "http://[redacted].xyz/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].xyz/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].cn/",
      "http://[redacted].com/k5.asp",
      "http://[redacted].com/index.php",
      "http://[redacted].com/index.php",
      "http://[redacted].com",
      "http://[redacted].com",
      "http://[redacted].com/index.php",
      "http://[redacted].cn/k7.php",
      "http://[redacted].com/index.php",
      "http://[redacted].com/service.php",
      "http://[redacted].com/k9.php",
      "http://[redacted].cn/sitemap.xml"
    ],
    "forms": [
      {
        "method": "post"
      }
    ],
    "inputs": [
      {
        "type": "text",
        "name": "q",
        "value": "请输入搜索内容"
      }
    ],
    "scripts": [
      {
        "src": "/template/news/xbwseo02/static/js/common.js",
        "type": "text/javascript"
      },
      {
        "src": "/template/news/xbwseo02/static/js/forum.js",
        "type": "text/javascript"
      },
      {
        "src": "/template/news/xbwseo02/static/js/forum_viewthread.js",
        "type": "text/javascript"
      },
      {
        "type": "text/javascript"
      },
      {
        "language": "VBScript"
      }
    ],
    "spans": [
      {
        "class": [
          "name"
        ]
      }
    ]
  }
},
{
  "file": {
    "filename": "script_5",
    "depth": 1,
    "flavors": {
      "mime": [
        "text/plain"
      ],
      "external": [
        "vbscript"
      ]
    },
    "source": "ScanHtml",
    "scanner_list": [
      "ScanYara",
      "ScanHash",
      "ScanEntropy",
      "ScanHeader",
      "ScanVb",
      "ScanUrl"
    ],
    "size": 113073
  },
  "tree": {
    "node": "153e9833-3d47-4a4d-a098-41efcc6f799e",
    "parent": "7b9b9460-7943-4f9b-b7e0-c48653a1adbd",
    "root": "7b9b9460-7943-4f9b-b7e0-c48653a1adbd",
  },
  "hash": {
    "md5": "64659f52fd89e89171af1f7d9441f2f2",
    "sha1": "763b46a4493e413f74e25b191c553a504e1ce66b",
    "sha256": "5a07bc83f2de5cbf28fdeb25a792c41686998118c77ee45a9bb94072ab18a170",
    "ssdeep": "1536:cyLi+rffMxqNisaQx4V5roEIfGJZN8qbV76EX1UP09weXA3oJrusBTOy9dGCsQSz:cyfkMY+BES09JXAnyrZalI+YG"
  },
  "entropy": {
    "entropy": 4.0084789402784775
  },
  "header": {
    "header": "<!--\nDropFileName = \"svchost.exe\"\nWriteData = \"4D5"
  },
  "vb": {
    "tokens": [
      "Token.Operator",
      "Token.Punctuation",
      "Token.Text",
      "Token.Name",
      "Token.Literal.String",
      "Token.Keyword",
      "Token.Literal.Number.Integer"
    ],
    "names": [
      "DropFileName",
      "WriteData",
      "FSO",
      "CreateObject",
      "DropPath",
      "GetSpecialFolder",
      "FileExists",
      "FileObj",
      "CreateTextFile",
      "i",
      "Len",
      "Write",
      "Chr",
      "Mid",
      "Close",
      "WSHshell",
      "Run"
    ],
    "operators": [
      "<",
      "-",
      "=",
      "&",
      "/",
      ">"
    ],
    "strings": [
      "svchost.exe",
      "4D5A900003000000[truncated]",
      "Scripting.FileSystemObject",
      "\\\\",
      "&H",
      "WScript.Shell"
    ]
  }
}
```

### Identifying suspicious executables
Strelka supports parsing executables across Linux (ELF), Mac (Mach-O), and Windows (MZ). Metadata parsed from these executables can be verbose, including logging the functions imported by Mach-O and MZ files and the segments imported by ELF files. This level of detail allows analysts to fingerprint executables beyond todays common techniques (e.g. [imphash](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html)).

Below is a partial scan result for an MZ file that shows PE metadata.
```json
{
  "filename": "VirusShare_0b937eb777e92d13fb583c4a992208dd",
  "depth": 0,
  "scanner_list": [
    "ScanYara",
    "ScanHash",
    "ScanEntropy",
    "ScanHeader",
    "ScanExiftool",
    "ScanPe"
  ],
  "size": 1666443
},
{
  "total": {
    "sections": 8
  },
  "timestamp": "1992-06-19T22:22:17",
  "machine": {
    "id": 332,
    "type": "IMAGE_FILE_MACHINE_I386"
  },
  "image_magic": "32_BIT",
  "subsystem": "IMAGE_SUBSYSTEM_WINDOWS_GUI",
  "stack_reserve_size": 1048576,
  "stack_commit_size": 16384,
  "heap_reserve_size": 1048576,
  "heap_commit_size": 4096,
  "entry_point": 50768,
  "image_base": 4194304,
  "image_characteristics": [
    "IMAGE_FILE_RELOCS_STRIPPED",
    "IMAGE_FILE_EXECUTABLE_IMAGE",
    "IMAGE_FILE_LINE_NUMS_STRIPPED",
    "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
    "IMAGE_FILE_BYTES_REVERSED_LO",
    "IMAGE_FILE_32BIT_MACHINE",
    "IMAGE_FILE_BYTES_REVERSED_HI"
  ],
  "imphash": "03a57449e5cad93724ec1ab534741a15",
  "imports": [
    "kernel32.dll",
    "user32.dll",
    "oleaut32.dll",
    "advapi32.dll",
    "comctl32.dll"
  ],
  "import_functions": [
    {
      "import": "kernel32.dll",
      "functions": [
        "DeleteCriticalSection",
        "LeaveCriticalSection",
        "EnterCriticalSection",
        "InitializeCriticalSection",
        "VirtualFree",
        "VirtualAlloc",
        "LocalFree",
        "LocalAlloc",
        "WideCharToMultiByte",
        "TlsSetValue",
        "TlsGetValue",
        "MultiByteToWideChar",
        "GetModuleHandleA",
        "GetLastError",
        "GetCommandLineA",
        "WriteFile",
        "SetFilePointer",
        "SetEndOfFile",
        "RtlUnwind",
        "ReadFile",
        "RaiseException",
        "GetStdHandle",
        "GetFileSize",
        "GetSystemTime",
        "GetFileType",
        "ExitProcess",
        "CreateFileA",
        "CloseHandle",
        "VirtualQuery",
        "VirtualProtect",
        "Sleep",
        "SetLastError",
        "SetErrorMode",
        "RemoveDirectoryA",
        "GetWindowsDirectoryA",
        "GetVersionExA",
        "GetUserDefaultLangID",
        "GetSystemInfo",
        "GetSystemDefaultLCID",
        "GetProcAddress",
        "GetModuleHandleA",
        "GetModuleFileNameA",
        "GetLocaleInfoA",
        "GetLastError",
        "GetFullPathNameA",
        "GetFileAttributesA",
        "GetExitCodeProcess",
        "GetEnvironmentVariableA",
        "GetCurrentProcess",
        "GetCommandLineA",
        "GetCPInfo",
        "FormatMessageA",
        "DeleteFileA",
        "CreateProcessA",
        "CreateDirectoryA",
        "CloseHandle"
      ]
    },
    {
      "import": "user32.dll",
      "functions": [
        "MessageBoxA",
        "TranslateMessage",
        "SetWindowLongA",
        "PeekMessageA",
        "MsgWaitForMultipleObjects",
        "MessageBoxA",
        "LoadStringA",
        "GetSystemMetrics",
        "ExitWindowsEx",
        "DispatchMessageA",
        "DestroyWindow",
        "CreateWindowExA",
        "CallWindowProcA",
        "CharPrevA",
        "CharNextA"
      ]
    },
    {
      "import": "oleaut32.dll",
      "functions": [
        "VariantChangeTypeEx",
        "VariantCopyInd",
        "VariantClear",
        "SysStringLen",
        "SysAllocStringLen"
      ]
    },
    {
      "import": "advapi32.dll",
      "functions": [
        "RegQueryValueExA",
        "RegOpenKeyExA",
        "RegCloseKey",
        "OpenProcessToken",
        "LookupPrivilegeValueA",
        "AdjustTokenPrivileges"
      ]
    },
    {
      "import": "comctl32.dll",
      "functions": [
        "InitCommonControls"
      ]
    }
  ],
  "resources": [
    {
      "type": "RT_ICON",
      "id": 1043,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 86796,
      "size": 296,
      "sha256": "f59f62e7843b3ff992cf769a3c608acd4a85a38b3b302cda8507b75163659d7b",
      "sha1": "4f6f7d9973b47063aa5353225a2bc5a76aa2a96a",
      "md5": "c5af786bfd9fd1c53c8fe9f0bd9ce38b",
      "language": "LANG_DUTCH",
      "sub_language": "SUBLANG_DUTCH"
    },
    {
      "type": "RT_ICON",
      "id": 1043,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 87092,
      "size": 1384,
      "sha256": "dc785b2a3e4ea82bd34121cc04e80758e221f11ee686fcfd87ce49f8e6730b22",
      "sha1": "6881cba71174502883d53a8885fb90dad81fd0c0",
      "md5": "0a451222f7037983439a58e3b44db529",
      "language": "LANG_DUTCH",
      "sub_language": "SUBLANG_DUTCH"
    },
    {
      "type": "RT_ICON",
      "id": 1043,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 88476,
      "size": 744,
      "sha256": "ca8fc96218d0a7e691dd7b95da05a27246439822d09b829af240523b28fd5bb3",
      "sha1": "b849a2b9901473810b5d74e6703be78c3a7e64e3",
      "md5": "90ed3aac2a942e3067e6471b32860e77",
      "language": "LANG_DUTCH",
      "sub_language": "SUBLANG_DUTCH"
    },
    {
      "type": "RT_ICON",
      "id": 1043,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 89220,
      "size": 2216,
      "sha256": "3bbacbad1458254c59ad7d0fd9bea998d46b70b8f8dcfc56aad561a293ffdae3",
      "sha1": "f54685a8a314e6f911c75cf7554796212fb17c3e",
      "md5": "af05dd5bd4c3b1fc94922c75ed4f9519",
      "language": "LANG_DUTCH",
      "sub_language": "SUBLANG_DUTCH"
    },
    {
      "type": "RT_STRING",
      "id": 0,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 91436,
      "size": 754,
      "sha256": "2c0d32398e3c95657a577c044cc32fe24fa058d0c32e13099b26fd678de8354f",
      "sha1": "4f9885ae629e83464e313af5254ef86f01accd0b",
      "md5": "bbf4b644f9dd284b35eb31573d0df2f7",
      "language": "LANG_NEUTRAL",
      "sub_language": "SUBLANG_NEUTRAL"
    },
    {
      "type": "RT_STRING",
      "id": 0,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 92192,
      "size": 780,
      "sha256": "840989e0a92f2746ae60b8e3efc1a39bcca17e82df3634c1643d76141fc75bb3",
      "sha1": "ff0db7d2f48d85ceb3539b21ebe9d0ca3443f1da",
      "md5": "ac2a0551cb90f91d779ee8622682dfb1",
      "language": "LANG_NEUTRAL",
      "sub_language": "SUBLANG_NEUTRAL"
    },
    {
      "type": "RT_STRING",
      "id": 0,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 92972,
      "size": 718,
      "sha256": "26bda4da3649a575157a6466468a0a86944756643855954120fd715f3c9c7f78",
      "sha1": "7375e693629ce6bbd1a0419621d094bcd2c67bb7",
      "md5": "c99b474c52df3049dfb38b5308f2827d",
      "language": "LANG_NEUTRAL",
      "sub_language": "SUBLANG_NEUTRAL"
    },
    {
      "type": "RT_STRING",
      "id": 0,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 93692,
      "size": 104,
      "sha256": "d786490af7fe66042fb4a7d52023f5a1442f9b5e65d067b9093d1a128a6af34c",
      "sha1": "249013a10cde021c713ba2dc8912f9e05be35735",
      "md5": "aec4e28ea9db1361160cde225d158108",
      "language": "LANG_NEUTRAL",
      "sub_language": "SUBLANG_NEUTRAL"
    },
    {
      "type": "RT_STRING",
      "id": 0,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 93796,
      "size": 180,
      "sha256": "00a0794f0a493c167f64ed8b119d49bdc59f76bb35e5c295dc047095958ee2fd",
      "sha1": "066052030d0a32310da8cb5a51d0590960a65f32",
      "md5": "c76a8843204c0572bca24ada35abe8c7",
      "language": "LANG_NEUTRAL",
      "sub_language": "SUBLANG_NEUTRAL"
    },
    {
      "type": "RT_STRING",
      "id": 0,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 93976,
      "size": 174,
      "sha256": "34973a8a33b90ec734bd328198311f579666d5aeb04c94f469ebb822689de3c3",
      "sha1": "1f5e4c73965fea1d1f729efbe7568dcd081a2168",
      "md5": "4bd4f3f6d918ba49d8800ad83d277a86",
      "language": "LANG_NEUTRAL",
      "sub_language": "SUBLANG_NEUTRAL"
    },
    {
      "type": "RT_GROUP_ICON",
      "id": 1033,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 94152,
      "size": 62,
      "sha256": "44b095a62d7e401671f57271e6cada367bb55cf7b300ef768b3487b841facd3c",
      "sha1": "4aa3239c2c59fa5f246b0dd68da564e529b98ff4",
      "md5": "f6262f462f61a1af1cac10cf4b790e5a",
      "language": "LANG_ENGLISH",
      "sub_language": "SUBLANG_ENGLISH_US"
    },
    {
      "type": "RT_VERSION",
      "id": 1033,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 94216,
      "size": 936,
      "sha256": "317a33004d3895b035961ccd83e22cdb39378708df0374387d389dd47f365c39",
      "sha1": "91d40710682b935fe1f3c66379901f90c444bac3",
      "md5": "6918486caeb42f838f9d8f0cc4d692dd",
      "language": "LANG_ENGLISH",
      "sub_language": "SUBLANG_ENGLISH_US"
    },
    {
      "type": "RT_MANIFEST",
      "id": 1033,
      "name": "IMAGE_RESOURCE_DATA_ENTRY",
      "offset": 95152,
      "size": 649,
      "sha256": "6cc41297efef410e2c23b74b2333cafa10b1e93e7dbcf4c683f37ad49ac1e92a",
      "sha1": "901d01bf4040d01986ed704587cb1c989d7f3b93",
      "md5": "c047a23817cac3cf4b6ade2cce0f2452",
      "language": "LANG_ENGLISH",
      "sub_language": "SUBLANG_ENGLISH_US"
    }
  ],
  "sections": [
    {
      "name": "CODE",
      "flags": [
        "IMAGE_SCN_CNT_CODE",
        "IMAGE_SCN_MEM_EXECUTE",
        "IMAGE_SCN_MEM_READ"
      ],
      "structure": "IMAGE_SECTION_HEADER"
    },
    {
      "name": "DATA",
      "flags": [
        "IMAGE_SCN_CNT_INITIALIZED_DATA",
        "IMAGE_SCN_MEM_READ",
        "IMAGE_SCN_MEM_WRITE"
      ],
      "structure": "IMAGE_SECTION_HEADER"
    },
    {
      "name": "BSS",
      "flags": [
        "IMAGE_SCN_MEM_READ",
        "IMAGE_SCN_MEM_WRITE"
      ],
      "structure": "IMAGE_SECTION_HEADER"
    },
    {
      "name": ".idata",
      "flags": [
        "IMAGE_SCN_CNT_INITIALIZED_DATA",
        "IMAGE_SCN_MEM_READ",
        "IMAGE_SCN_MEM_WRITE"
      ],
      "structure": "IMAGE_SECTION_HEADER"
    },
    {
      "name": ".tls",
      "flags": [
        "IMAGE_SCN_MEM_READ",
        "IMAGE_SCN_MEM_WRITE"
      ],
      "structure": "IMAGE_SECTION_HEADER"
    },
    {
      "name": ".rdata",
      "flags": [
        "IMAGE_SCN_CNT_INITIALIZED_DATA",
        "IMAGE_SCN_MEM_SHARED",
        "IMAGE_SCN_MEM_READ"
      ],
      "structure": "IMAGE_SECTION_HEADER"
    },
    {
      "name": ".reloc",
      "flags": [
        "IMAGE_SCN_CNT_INITIALIZED_DATA",
        "IMAGE_SCN_MEM_SHARED",
        "IMAGE_SCN_MEM_READ"
      ],
      "structure": "IMAGE_SECTION_HEADER"
    },
    {
      "name": ".rsrc",
      "flags": [
        "IMAGE_SCN_CNT_INITIALIZED_DATA",
        "IMAGE_SCN_MEM_SHARED",
        "IMAGE_SCN_MEM_READ"
      ],
      "structure": "IMAGE_SECTION_HEADER"
    }
  ]
}
```

### Identifying suspicious text
Strelka supports extracting body text from document files (MS Word, PDF, etc.) and optical text from image files (using Optical Character Recognition, OCR). Extracted text is treated like any other file -- it is hashed, scanned with YARA, and parsed with text-specific scanners. This makes it relatively easy to track patterns in phishing activity, especially when threat actors leverage indirect methods of malware delivery (e.g. sending the target a hyperlink in an email body).

Below is a complete scan result for a text file that appears to be a shell script containing an IP address. The IP address is redacted to prevent accidental navigation.
```json
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

### Interacting with external systems
At release, Strelka supports sending files to a Cuckoo sandbox and sending VBScript files to a networked instance of MMBot.

Below is a partial scan result for a document file that contains VBA/VBScript, this shows the maliciousness prediction and metadata retrieved from MMBot.
```json
{
  "file": {
    "filename": "/samples/benign.xlsm",
    "depth": 0,
    "scanner_list": [
      "ScanYara",
      "ScanHash",
      "ScanEntropy",
      "ScanHeader",
      "ScanExiftool",
      "ScanZip"
    ],
    "size": 10906
  },
  "tree": {
    "node": "12db8e8b-cfea-4290-85e0-8314ec00289f",
    "root": "12db8e8b-cfea-4290-85e0-8314ec00289f"
  }
},
{
  "file": {
    "filename": "ThisWorkbook.cls",
    "depth": 2,
    "flavors": {
      "yara": [
        "vb_file"
      ],
      "mime": [
        "text/plain"
      ]
    },
    "source": "ScanVba",
    "scanner_list": [
      "ScanYara",
      "ScanHash",
      "ScanEntropy",
      "ScanHeader",
      "ScanVb",
      "ScanMmbot",
      "ScanUrl"
    ],
    "size": 305
  },
  "tree": {
    "node": "c32ae623-9f48-4d0e-ac48-2ca68770863c",
    "parent": "13cb69ec-c7ce-433d-bd2e-14ebbfee1e3f",
    "root": "13cb69ec-c7ce-433d-bd2e-14ebbfee1e3f"
},
  "hash": {
    "md5": "b59c5dbc9757e748ff31c4ef3478af98",
    "sha1": "4a864f065b59cd4ebe031f2cbc70aecd5331a2de",
    "sha256": "14de0425a62586687c3d59b7d3d7dc60268f989ab7e07a61403525064d98502a",
    "ssdeep": "6:YhH0shm7FWSvVG/4H3HcM25E3YRV3opedT1Xdv8SAFYDsoS:Y7gZWaVW4B25dTJaoS"
  },
  "entropy": {
    "entropy": 4.838185555972263
  },
  "header": {
    "header": "Attribute VB_Name = \"ThisWorkbook\"\r\nAttribute VB_B"
  },
  "vb": {
    "tokens": [
      "Token.Name",
      "Token.Operator",
      "Token.Literal.String",
      "Token.Text",
      "Token.Keyword"
    ],
    "names": [
      "Attribute",
      "VB_Name",
      "VB_Base",
      "VB_GlobalNameSpace",
      "VB_Creatable",
      "VB_PredeclaredId",
      "VB_Exposed",
      "VB_TemplateDerived",
      "VB_Customizable"
    ],
    "operators": [
      "="
    ],
    "strings": [
      "ThisWorkbook",
      "0{00020819-0000-0000-C000-000000000046}"
    ]
  },
  "mmbot": {
    "confidence": 0.94,
    "prediction": "benign",
    "lang_features": "cpl_codepanes_declare_getselection_calendar",
    "avg_param_per_func": 0,
    "cnt_comment_loc_ratio": 0,
    "cnt_comments": 0,
    "cnt_function_loc_ratio": 0,
    "cnt_functions": 0,
    "cnt_loc": 8,
    "entropy_chars": 2.37,
    "entropy_func_names": 0,
    "entropy_words": 3.35,
    "mean_loc_per_func": 8
  },
  "yara": {
    "flags": [ "compiling_error" ]
  }
}
```

## Contributing
Guidelines for contributing can be found [here](https://github.com/target/strelka/blob/master/CONTRIBUTING.md).

## Related Projects
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [File Scanning Framework](https://github.com/EmersonElectricCo/fsf)
* [Assemblyline](https://cybercentrecanada.github.io/assemblyline4_docs/)

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license.
