# Strelka
Strelka is a real-time file scanning system used for threat hunting, threat detection, and incident response. Based on the design established by Lockheed Martin's [Laika BOSS](https://github.com/lmco/laikaboss) and similar projects (see: [related projects](#related-projects)), Strelka's purpose is to perform file extraction and metadata collection at huge scale.

Strelka differs from its sibling projects in a few significant ways:
* Codebase is Python 3 (minimum supported version is 3.6)
* Designed for non-interactive, distributed systems (network security monitoring sensors, live response scripts, disk/memory extraction, etc.)
* Supports direct and remote file requests (Amazon S3, Google Cloud Storage, etc.) with optional encryption and authentication
* Uses widely supported networking, messaging, and data libraries/formats (ZeroMQ, protocol buffers, YAML, JSON)
* Built-in scan result logging and log management (compatible with Filebeat/ElasticStack, Splunk, etc.)

[![Target’s CFC-Open-Source Slack](https://cfc-slack-inv.herokuapp.com/badge.svg?colorA=155799&colorB=159953)](https://cfc-slack-inv.herokuapp.com/)

## Table of Contents
* [FAQ](#frequently-asked-questions)
* [Installation](#installation)
    * [Ubuntu 18.04 LTS](#ubuntu-1804-lts)
    * [Docker](#docker)
* [Quickstart](#quickstart)
* [Deployment](#deployment)
    * [Utilities](#utilities)
        * [strelka.py](#strelkapy)
        * [strelka_dirstream.py](#strelka_dirstreampy)
        * [strelka_user_client.py](#strelka_user_clientpy)
        * [generate_curve_certificates.py](#generate_curve_certificatespy)
        * [validate_yara.py](#validate_yarapy)
    * [Configuration Files](#configuration-files)
        * [Strelka Configuration](#strelka-configuration-strelkapy)
          * [Daemon Configuration](#daemon-configuration)
          * [Remote Configuration](#remote-configuration)
          * [Scan Configuration](#scan-configuration)
        * [Python Logging Configuration](#python-logging-configuration-strelkapy)
        * [DirStream Configuration](#dirstream-configuration-strelka_dirstreampy)
    * [Encryption and Authentication](#encryption-and-authentication)
        * [CurveZMQ](#curvezmq)
        * [Using Curve](#using-curve)
    * [Clusters](#clusters)
        * [General Recommendations](#general-recommendations)
        * [Sizing Considerations](#sizing-considerations)
        * [Docker Considerations](#docker-considerations)
        * [Management](#management)
* [Architecture](#architecture)
    * [Overview](#overview)
    * [Networking](#networking)
    * [Messaging](#messaging)
    * [Data](#data)
* [Design](#design)
    * [Communication](#communication)
        * [Client-to-Broker](#client-to-broker)
        * [Broker-to-Worker](#broker-to-worker)
    * [File Distribution, Scanners, Flavors, and Tastes](#file-distribution-scanners-flavors-and-tastes)
    * [File Requests](#file-requests)
        * [Direct](#direct)
        * [Remote](#remote)
        * [`FileRequest` protobuf](#filerequest-protobuf)
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
* Modern codebase (Python 3.6+)
* More scanners (40+ at release) and file types (60+ at release) than [related projects](#related-projects)
* Supports [direct and remote file requests](#file-requests)
* Built-in [encryption and authentication](#encryption-and-authentication) for client connections
* Built using [libraries and formats](#architecture) that allow cross-platform, cross-language support

### "Are Strelka's scanners compatible with Laika BOSS, File Scanning Framework, or Assemblyline?"
Due to differences in design, Strelka's scanners are not directly compatible with Laika BOSS, File Scanning Framework, or Assemblyline. With some effort, most scanners can likely be ported to the other projects.

### "Is Strelka an intrusion detection system (IDS)?"
Strelka shouldn't be thought of as an IDS, but it can be used for threat detection through YARA rule matching and downstream metadata interpretation. Strelka's design follows the philosophy established by other popular metadata collection systems (Bro, Sysmon, Volatility, etc.): it extracts data and leaves the decision-making up to the user.

### "Does it work at scale?"
Everyone has their own definition of "at scale," but we have been using Strelka and systems like it to scan up to 100 million files each day for over a year and have never reached a point where the system could not scale to our needs -- as file volume and diversity increases, horizontally scaling the system should allow you to scan any number of files.

### "Doesn't this use a lot of bandwidth?"
Yep! Strelka isn't designed to operate in limited bandwidth environments, but we have experimented with solutions to this and there are tricks you can use to reduce bandwidth. These are what we've found most successful:
* Reduce the total volume of files sent to Strelka
* Use a tracking system to only send unique files to Strelka (networked Redis servers are especially useful for this)
* Use [traffic control (tc)](https://linux.die.net/man/8/tc) to shape connections to Strelka

### "Should I run my Strelka cluster on my Bro/Suricata network sensor?"
No! Strelka clusters run CPU-intensive processes that will negatively impact system-critical applications like Bro and Suricata. If you want to integrate a network sensor with Strelka, then use [`strelka_dirstream.py`](#strelka_dirstreampy). This utility is capable of sending millions of files per day from a single network sensor to a Strelka cluster without impacting system-critical applications.

### "I have other questions!"
Please file an issue or contact the project team at [TTS-CFC-OpenSource@target.com](mailto:TTS-CFC-OpenSource@target.com). The project lead can also be reached on Twitter at [@jshlbrd](https://twitter.com/jshlbrd).

## Installation
The recommended operating system for Strelka is Ubuntu 18.04 LTS (Bionic Beaver) -- it may work with earlier versions of Ubuntu if the appropriate packages are installed. We recommend using the Docker container for production deployments and welcome pull requests that add instructions for installing on other operating systems.

### Ubuntu 18.04 LTS
1. Update packages and install build packages
  ```sh
  apt-get update && apt-get install --no-install-recommends automake build-essential curl gcc git libtool make python3-dev python3-pip python3-wheel
  ```

2. Install runtime packages
  ```sh
  apt-get install --no-install-recommends antiword libarchive-dev libfuzzy-dev libimage-exiftool-perl libmagic-dev libssl-dev python3-setuptools tesseract-ocr unrar upx jq
  ```

2. Install pip3 packages
    ```sh
    pip3 install beautifulsoup4 boltons boto3 gevent google-cloud-storage html5lib inflection interruptingcow jsbeautifier libarchive-c lxml git+https://github.com/aaronst/macholibre.git olefile oletools pdfminer.six pefile pgpdump3 protobuf pyelftools pygments pyjsparser pylzma git+https://github.com/jshlbrd/pyopenssl.git python-docx git+https://github.com/jshlbrd/python-entropy.git python-keystoneclient python-magic python-swiftclient pyyaml pyzmq rarfile requests rpmfile schedule ssdeep tnefparse
    ```

3. Install YARA
  ```sh
  curl -OL https://github.com/VirusTotal/yara/archive/v3.8.1.tar.gz
  tar -zxvf v3.8.1.tar.gz
  cd yara-3.8.1/
  ./bootstrap.sh
  ./configure --with-crypto --enable-dotnet --enable-magic
  make && make install && make check
  echo "/usr/local/lib" >> /etc/ld.so.conf
  ldconfig
  ```

4. Install yara-python
  ```sh
  curl -OL https://github.com/VirusTotal/yara-python/archive/v3.8.1.tar.gz  
  tar -zxvf v3.8.1.tar.gz  
  cd yara-python-3.8.1/  
  python3 setup.py build --dynamic-linking  
  python3 setup.py install
  ```

5. Create Strelka directories
    ```sh
    mkdir /var/log/strelka/ && mkdir /opt/strelka/
    ```

5. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

6. Compile the Strelka protobuf
    ```sh
    cd /opt/strelka/server/ && protoc --python_out=. strelka.proto
    ```

7. (Optional) Install the Strelka utilities
    ```sh
    cd /opt/strelka/ && python3 setup.py -q build && python3 setup.py -q install && python3 setup.py -q clean --all
    ```

### Docker
1. Clone this repository
    ```sh
    git clone https://github.com/target/strelka.git /opt/strelka/
    ```

2. Build the container
    ```sh
    cd /opt/strelka/ && docker build -t strelka .
    ```

## Quickstart
By default, Strelka is configured to use a minimal "quickstart" deployment that allows users to test the system. This configuration **is not recommended** for production deployments. Using two Terminal windows, do the following:

Terminal 1
```
$ strelka.py
```

Terminal 2:
```
$ strelka_user_client.py --broker 127.0.0.1:5558 --path <path to the file to scan>
$ cat /var/log/strelka/*.log | jq .
```

Terminal 1 runs a Strelka cluster (broker, 4 workers, and log rotation) with debug logging and Terminal 2 is used to send file requests to the cluster and read the scan results.

## Deployment
### Utilities
Strelka's design as a distributed system creates the need for client-side and server-side utilities. Client-side utilities provide methods for sending file requests to a cluster and server-side utilities provide methods for distributing and scanning files sent to a cluster.

#### strelka.py
`strelka.py` is a non-interactive, server-side utility that contains everything needed for running a large-scale, distributed Strelka cluster. This includes:
* Capability to run servers in any combination of broker/workers
   * Broker distributes file tasks to workers
   * Workers perform file analysis on tasks
* On-disk scan result logging
   * Configurable log rotation and management
   * Compatible with external log shippers (e.g. Filebeat, Splunk Universal Forwarder, etc.)
* Supports encryption and authentication for connections between clients and brokers
* Self-healing child processes (brokers, workers, log management)

This utility is managed with two configuration files: [`etc/strelka/strelka.yml`](#strelka-configuration-strelkapy) and [`etc/strelka/pylogging.ini`](#python-logging-configuration-strelkapy).

The help page for `strelka.py` is shown below:
```
usage: strelka.py [options]

runs Strelka as a distributed cluster.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug messages to the console
  -c STRELKA_CFG, --strelka-config STRELKA_CFG
                        path to strelka configuration file
  -l LOGGING_INI, --logging-ini LOGGING_INI
                        path to python logging configuration file
```

#### strelka_dirstream.py
`strelka_dirstream.py` is a non-interactive, client-side utility used for sending files from a directory to a Strelka cluster in near real-time. This utility uses inotify to watch the directory and sends files to the cluster as soon as possible after they are written.

Additionally, for select file sources, this utility can parse metadata embedded in the file's filename and send it to the cluster as external metadata. Bro network sensors are currently the only supported file source, but other application-specific sources can be added.

Using the utility with Bro requires no modification of the Bro source code, but it does require the network sensor to run a Bro script that enables file extraction. We recommend using our stub Bro script (`etc/bro/extract-strelka.bro`) to extract files. Other extraction scripts will also work, but they will not parse Bro's metadata.

This utility is managed with one configuration file: [`etc/dirstream/dirstream.yml`](#dirstream-configuration-strelka_dirstreampy).

The help page for `strelka_dirstream.py` is shown below:
```
usage: strelka_dirstream.py [options]

sends files from a directory to a Strelka cluster in near real-time.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug messages to the console
  -c DIRSTREAM_CFG, --dirstream-config DIRSTREAM_CFG
                        path to dirstream configuration file
```

#### strelka_user_client.py
`strelka_user_client.py` is a user-driven, client-side utility that is used for sending ad-hoc file requests to a cluster. This client should be used when file analysis is needed for a specific file or group of files -- it is explicitly designed for users and should not be expected to perform long-lived or fully automated file requests. We recommend using this utility as an example of what is required in building new client utilities.

Using this utility, users can send three types of file requests:
* Individual file
* Directory of files
* Remote file (see: [remote file requests](#remote))

The help page for `strelka_user_client.py` is shown below:
```
usage: strelka_user_client.py [options]

sends ad-hoc file requests to a Strelka cluster.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug messages to the console
  -b BROKER, --broker BROKER
                        network address and network port of the broker (e.g.
                        127.0.0.1:5558)
  -p PATH, --path PATH  path to the file or directory of files to send to the
                        broker
  -l LOCATION, --location LOCATION
                        JSON representation of a location for the cluster to
                        retrieve files from
  -t TIMEOUT, --timeout TIMEOUT
                        amount of time (in seconds) to wait until a file
                        transfer times out
  -bpk BROKER_PUBLIC_KEY, --broker-public-key BROKER_PUBLIC_KEY
                        location of the broker Curve public key certificate
                        (this option enables curve encryption and must be used
                        if the broker has curve enabled)
  -csk CLIENT_SECRET_KEY, --client-secret-key CLIENT_SECRET_KEY
                        location of the client Curve secret key certificate
                        (this option enables curve encryption and must be used
                        if the broker has curve enabled)
  -ug, --use-green      determines if PyZMQ green should be used, which can
                        increase performance at the risk of message loss
```

#### generate_curve_certificates.py
`generate_curve_certificates.py` is a utility used for generating broker and worker Curve certificates. This utility is required for setting up Curve encryption/authentication.

The help page for `generate_curve_certificates.py` is shown below:
```
usage: generate_curve_certificates.py [options]

generates curve certificates used by brokers and clients.

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  path to store keys in (defaults to current working
                        directory)
  -b, --broker          generate curve certificates for a broker
  -c, --client          generate curve certificates for a client
  -cf CLIENT_FILE, --client-file CLIENT_FILE
                        path to a file containing line-separated list of
                        clients to generate keys for, useful for creating many
                        client keys at once
```

#### validate_yara.py
`validate_yara.py` is a utility used for recursively validating a directory of YARA rules files. This can be useful when debugging issues related to the `ScanYara` scanner.

The help page for `validate_yara.py` is shown below:
```
usage: validate_yara.py [options]

validates YARA rules files.

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  path to directory containing YARA rules
  -e, --error           boolean that determines if warnings should cause
                        errors
```

### Configuration Files
Strelka uses YAML for configuring client-side and server-side utilities. We recommend using the default configurations and modifying the options as needed.

#### Strelka Configuration (`strelka.py`)
Strelka's cluster configuration file is stored in `etc/strelka/strelka.yml` and contains three sections: daemon, remote, and scan.

##### Daemon Configuration
The daemon configuration contains five sub-sections: processes, network, broker, workers, and logrotate.

The "processes" section controls the processes launched by the daemon. The configuration options are:
* "run_broker": boolean that determines if the server should run a Strelka broker process (defaults to True)
* "run_workers": boolean that determines if the server should run Strelka worker processes (defaults to True)
* "run_logrotate": boolean that determines if the server should run a Strelka log rotation process (defaults to True)
* "worker_count": number of workers to spawn (defaults to 4)
* "shutdown_timeout": amount of time (in seconds) that will elapse before the daemon forcibly kills child processes after they have received a shutdown command (defaults to 45 seconds)

The "network" section controls network connectivity. The configuration options are:
* "broker": network address of the broker (defaults to 127.0.0.1)
* "request_socket_port": network port used by clients to send file requests to the broker (defaults to 5558)
* "task_socket_port": network port used by workers to receive tasks from the broker (defaults to 5559)

The "broker" section controls settings related to the broker process. The configuration options are:
* "poller_timeout": amount of time (in milliseconds) that the broker polls for client requests and worker statuses (defaults to 1000 milliseconds)
* "broker_secret_key": location of the broker Curve secret key certificate (enables Curve encryption, requires clients to use Curve, defaults to None)
* "client_public_keys": location of the directory containing client Curve public key certificates (enables Curve encryption and authentication, requires clients to use Curve, defaults to None)
* "prune_frequency": frequency (in seconds) at which the broker prunes dead workers (defaults to 5 seconds)
* "prune_delta": delta (in seconds) that must pass since a worker last checked in with the broker before it is considered dead and is pruned (defaults to 10 seconds)

The "workers" section controls settings related to worker processes. The configuration options are:
* "task_socket_reconnect": amount of time (in milliseconds) that the task socket will attempt to reconnect in the event of TCP disconnection, this will have additional jitter applied (defaults to 100ms plus jitter)
* "task_socket_reconnect_max": maximum amount of time (in milliseconds) that the task socket will attempt to reconnect in the event of TCP disconnection, this will have additional jitter applied (defaults to 4000ms plus jitter)
* "poller_timeout": amount of time (in milliseconds) that workers poll for file tasks (defaults to 1000 milliseconds)
* "file_max": number of files a worker will process before shutting down (defaults to 10000)
* "time_to_live": amount of time (in minutes) that a worker will run before shutting down (defaults to 30 minutes)
* "heartbeat_frequency": frequency (in seconds) at which a worker sends a heartbeat to the broker if it has not received any file tasks (defaults to 10 seconds)
* "log_directory": location where worker scan results are logged to (defaults to /var/log/strelka/)
* "log_field_case": field case ("camel" or "snake") of the scan result log file data (defaults to camel)
* "log_bundle_events": boolean that determines if scan results should be bundled in single event as an array or in multiple events (defaults to True)

The "logrotate" section controls settings related to the log rotation process. The configuration options are:
* "directory": directory to run log rotation on (defaults to /var/log/strelka/)
* "compression_delta": delta (in minutes) that must pass since a log file was last modified before it is compressed (defaults to 15 minutes)
* "deletion_delta": delta (in minutes) that must pass since a compressed log file was last modified before it is deleted (defaults to 360 minutes / 6 hours)

##### Remote Configuration
The remote configuration contains one sub-section: remote.

The "remote" section controls how workers retrieve files from remote file stores. Google Cloud Storage, Amazon S3, OpenStack Swift, and HTTP file stores are supported. All options in this configuration file are optionally read from environment variables if they are "null". The configuration options are:
* "remote_timeout": amount of time (in seconds) to wait before timing out individual file retrieval
* "remote_retries": number of times individual file retrieval will be re-attempted in the event of a timeout
* "google_application_credentials": path to the Google Cloud Storage JSON credentials file
* "aws_access_key_id": AWS access key ID
* "aws_secret_access_key": AWS secret access key
* "aws_default_region": default AWS region
* "st_auth_version": OpenStack authentication version (defaults to 3)
* "os_auth_url": OpenStack Keystone authentication URL
* "os_username": OpenStack username
* "os_password": OpenStack password
* "os_cert": OpenStack Keystone certificate
* "os_cacert": OpenStack Keystone CA Certificate
* "os_user_domain_name": OpenStack user domain
* "os_project_name": OpenStack project name
* "os_project_domain_name": OpenStack project domain
* "http_basic_user": HTTP Basic authentication username
* "http_basic_pass": HTTP Basic authentication password
* "http_verify": path to the CA bundle (file or directory) used for SSL verification (defaults to False, no verification)

##### Scan Configuration
The scan configuration contains two sub-sections: distribution and scanners.

The "distribution" section controls how files are distributed through the system. The configuration options are:
* "close_timeout": amount of time (in seconds) that a scanner can spend closing itself (defaults to 30 seconds)
* "distribution_timeout": amount of time (in seconds) that a single file can be distributed to all scanners (defaults to 1800 seconds / 30 minutes)
* "scanner_timeout": amount of time (in seconds) that a scanner can spend scanning a file (defaults to 600 seconds / 10 minutes, can be overridden per-scanner)
* "maximum_depth": maximum depth that child files will be processed by scanners
* "taste_mime_db": location of the MIME database used to taste files (defaults to None, system default)
* "taste_yara_rules": location of the directory of YARA files that contains rules used to taste files (defaults to etc/strelka/taste/)

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

#### Python Logging Configuration (`strelka.py`)
`strelka.py` uses an ini file (`etc/strelka/pylogging.ini`) to manage cluster-level statistics and information output by the Python logger. By default, this configuration file will log data to stdout and disable logging for packages imported by scanners.

#### DirStream Configuration (`strelka_dirstream.py`)
Strelka's dirstream configuration file is stored in `etc/dirstream/dirstream.yml` and contains two sub-sections: processes and workers.

The "processes" section controls the processes launched by the utility. The configuration options are:
* "shutdown_timeout": amount of time (in seconds) that will elapse before the utility forcibly kills child processes after they have received a shutdown command (defaults to 10 seconds)

The "workers" section controls directory settings and network settings for each worker that sends files to the Strelka cluster. This section is a list; adding multiple directory/network settings makes it so multiple directories can be monitored at once.
The configuration options are:
* "directory": directory that files are sent from (defaults to None)
* "source": application that writes files to the directory, used to control metadata parsing functionality (defaults to None)
* "meta_separator": unique string used to separate pieces of metadata in a filename, used to parse metadata and send it along with the file to the cluster (defaults to "S^E^P")
* "file_mtime_delta": delta (in seconds) that must pass since a file was last modified before it is sent to the cluster (defaults to 5 seconds)
* "delete_files": boolean that determines if files should be deleted after they are sent to the cluster (defaults to False)
* "broker": network address and network port of the broker (defaults to "127.0.0.1:5558")
* "timeout": amount of time (in seconds) to wait for a file to be successfully sent to the broker (defaults to 10)
* "use_green": boolean that determines if PyZMQ green should be used (this can increase performance at the risk of message loss, defaults to True)
* "broker_public_key": location of the broker Curve public key certificate (enables Curve encryption, must be used if the broker has Curve enabled)
* "client_secret_key": location of the client Curve secret key certificate (enables Curve encryption, must be used if the broker has Curve enabled)

To enable Bro support, a Bro file extraction script must be run by the Bro application; Strelka's file extraction script is stored in `etc/bro/extract-strelka.bro` and includes variables that can be redefined at Bro runtime. These variables are:
* "mime_table": table of strings (Bro `source`) mapped to a set of strings (Bro `mime_type`) -- this variable defines which file MIME types Bro extracts and is configurable based on the location Bro identified the file (e.g. extract `application/x-dosexec` files from SMTP, but not SMB or FTP)
* "filename_re": regex pattern that can extract files based on Bro `filename`
* "unknown_mime_source": set of strings (Bro `source`) that determines if files of an unknown MIME type should be extracted based on the location Bro identified the file (e.g. extract unknown files from SMTP, but not SMB or FTP)
* "meta_separator": string used in extracted filenames to separate embedded Bro metadata -- this must match the equivalent value in `etc/dirstream/dirstream.yml`
* "directory_count_interval": interval used to schedule how often the script checks the file count in the extraction directory
* "directory_count_threshold": int that is used as a trigger to temporarily disable file extraction if the file count in the extraction directory reaches the threshold

### Encryption and Authentication
Strelka has built-in, optional encryption and authentication for client connections provided by CurveZMQ.

#### CurveZMQ
CurveZMQ (Curve) is ZMQ's encryption and authentication protocol. Read more about it [here](http://curvezmq.org/page:read-the-docs).

#### Using Curve
Strelka uses Curve to encrypt and authenticate connections between clients and brokers. By default, Strelka's Curve support is setup to enable encryption but not authentication.

To enable Curve encryption, the broker must be loaded with a private key -- any clients connecting to the broker must have the broker's public key to successfully connect.

To enable Curve encryption and authentication, the broker must be loaded with a private key and a directory of client public keys -- any clients connecting to the broker must have the broker's public key and have their client key loaded on the broker to successfully connect.

The [`generate_curve_certificates.py`](#generate_curve_certificatespy) utility can be used to create client and broker certificates.

### Clusters
The following are recommendations and considerations to keep in mind when deploying clusters.

#### General Recommendations
The following recommendations apply to all clusters:
* Do not run workers on the same server as a broker
    * This puts the health of the entire cluster at risk if the server becomes over-utilized
* Do not over-allocate workers to CPUs
    * 1 worker per CPU
* Allocate at least 1GB RAM per worker
    * If workers do not have enough RAM, then there will be excessive memory errors
    * Big files (especially compressed files) require more RAM
    * In large clusters, diminishing returns begin above 4GB RAM per worker
* Allocate as much RAM as reasonable to the broker
    * ZMQ messages are stored entirely in memory -- in large deployments with many clients, the broker may use a lot of RAM if the workers cannot keep up with the number of file tasks

#### Sizing Considerations
Multiple variables should be considered when determining the appropriate size for a cluster:
* Number of file requests per second
* Type of file requests
    * Remote file requests take longer to process than direct file requests
* Diversity of files requested
    * Binary files take longer to scan than text files
* Number of YARA rules deployed
    * Scanning a file with 50,000 rules takes longer than scanning a file with 50 rules

The best way to properly size a cluster is to start small, measure performance, and scale out as needed.

#### Docker Considerations
Below is a list of considerations to keep in mind when running a cluster with Docker containers:
* Share volumes, not files, with the container
    * Strelka's workers will read configuration files and YARA rules files when they startup -- sharing volumes with the container ensures that updated copies of these files on the localhost are reflected accurately inside the container without needing to restart the container
* [Increase stop-timeout](https://docs.docker.com/engine/reference/commandline/run/#options)
    * By default, Docker will forcibly kill a container if it has not stopped after 10 seconds -- this value should be increased to **greater than** the `shutdown_timeout` value in `etc/strelka/strelka.yml`
* [Increase shm-size](https://docs.docker.com/engine/reference/commandline/run/#options)
    * By default, Docker limits a container's shm size to 64MB -- this can cause errors with Strelka scanners that utilize `tempfile`
* [Set logging options](https://docs.docker.com/config/containers/logging/configure/#supported-logging-drivers)
    * By default, Docker has no log limit for logs output by a container

#### Management
Due to its distributed design, we recommend using container orchestration (e.g. Kubernetes) or configuration management/provisioning (e.g. Ansible, SaltStack, etc.) systems for managing clusters.

## Architecture
### Overview
Strelka's architecture allows clients ("clients") to submit file requests to a single intake server ("broker") which distributes the requests as tasks to multiple processing servers ("workers"). A series of workers connected to a broker creates a "cluster." During file processing, files are sent through a series of metadata and file extraction modules ("scanners") via a user-defined distribution system ("tastes" and "flavors"); file scan results are logged to disk and can be sent to downstream analytics platforms (e.g. ElasticStack, Splunk, etc.).

This architecture makes the following deployments possible:
* 1-to-1 cluster (one client to one worker)
* 1-to-N cluster (one client to N workers)
* N-to-1 cluster (N clients to one worker)
* N-to-N cluster (N clients to N workers)

The most practical deployment is an N-to-N cluster -- this creates a fully scalable deployment that can be modified in-place without requiring cluster downtime.

### Networking
Clients, brokers, and workers communicate using TCP sockets in the ZeroMQ (ZMQ) networking library.

### Messaging
File requests are encoded as [protocol buffers](https://developers.google.com/protocol-buffers/) (protobuf). protobufs have a maximum message size of 2GB -- any attempts to send file requests bigger than the maximum message size will fail and we have observed inconsistent behavior with [direct file requests](#direct) larger than 1.5GB. We do not recommend scanning extremely large files (>1GB), but if you must, then we suggest using [remote file requests](#remote) to do so.

### Data
Configuration files are written in YAML format. Internal file metadata is written in JSON format according to [Google's JSON style guide](https://google.github.io/styleguide/jsoncstyleguide.xml). Timestamp metadata is formatted according to [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) (UTC in seconds).

## Design
### Communication
All communication occurs via ZMQ -- clients communicate unidirectionally with brokers and brokers communicate bidirectionally with workers (clients never communicate with workers).

#### Client-to-Broker
Client-to-broker communication uses ZMQ's PUSH-PULL pattern -- clients _push_ file requests to a broker which _pulls_ the request. The pattern is visualized like this:
```
Client (PUSH) ---> (PULL) Broker
```

#### Broker-to-Worker
Broker-to-worker communication uses ZMQ's ROUTER-DEALER pattern.

The ROUTER-DEALER pattern enables bidirectional communication between the broker and worker. When a worker starts up or completes a file scan, it sends a ready status  (`\x01`) to the broker signaling that it is ready to receive new tasks. As the broker receives file requests from clients, it uses a FIFO queue (`worker_pool`) to distribute tasks to workers. On shutdown (planned or unplanned), the worker sends a shutdown status  (`\x10`) to the broker signaling that it is no longer available to receive new tasks.

Strelka uses a modified [paranoid pirate pattern](http://zguide.zeromq.org/php:chapter4#toc5) to manage dead workers. Workers send a heartbeat (status `\x01`) to the broker every N seconds according to "heartbeat_frequency" in the [daemon configuration](#daemon-configuration). This ensures that the broker knows each worker is alive and, if the broker goes offline and comes back online, that the broker eventually has an up-to-date worker pool. Similarly, the broker prunes dead workers from the worker pool every N seconds according to "prune_frequency" in the [daemon configuration](#daemon-configuration) if workers have not sent a heartbeat within a delta determined by "prune_delta". This ensures that dead workers do not remain in the worker pool.

This communication pattern is used hundreds-to-thousands of times during the life of a single worker. The pattern is visualized like this:
```
Broker (ROUTER) <---> (DEALER) Worker
```

### File Distribution, Scanners, Flavors, and Tastes
Strelka's file distribution assigns scanners (`server/scanners/*`) to files based on a system of "flavors" and "tastes". Flavors describe the type of file being distributed through the system and come in three types:
* MIME flavors -- assigned by libmagic (e.g. "application/zip")
* YARA flavors -- assigned by YARA rule matches (e.g. "zip_file")
* External flavors -- assigned by a file request or a parent file (e.g. "zip")

As files enter the system, they are tasted (e.g. scanned with YARA), their flavor is identified, and the flavor is checked for a corresponding mapping in the scan configuration (`etc/strelka/strelka.yml`, see [Scan Configuration](#scan-configuration) for more details) -- flavors are the primary method through which scanners are assigned to files.

### File Requests
Strelka supports two types of file requests, direct and remote, that are made via a shared protobuf message. A single cluster can concurrently support both types of file requests.

#### Direct
A direct file request is one where the client includes the file's data in the protobuf message (data is stored in the `data` key). This is the default method for submitting files and is handled via the client library function `request_to_protobuf`.

#### Remote
A remote file request is one where the client includes the file's location details in the protobuf message (location details are stored in the `location` key). Location details are stored in the protobuf as a map of strings (the client library function `request_to_protobuf` will automatically convert a Python dictionary to the correct format). A file's location details vary depending on where the file is hosted.

For files stored in Amazon S3, Google Cloud Storage, and OpenStack Swift, `location` follows this format:
* "type": type of file store the file is located in (must be set to "amazon", "google", or "openstack")
* "bucket": bucket/container the file is located in
* "object": name of the file

For files stored on HTTP servers, `location` follows this format:
* "type": must be set to "http"
* "object": URL of the file

Authentication to remote file stores is handled via `etc/strelka/strelka.yml` (see [Remote Configuration](#remote-configuration) for more details).

#### `FileRequest` protobuf
Below is a description of the keys included in the `FileRequest` protobuf. All keys are optional. This information can be used to create a valid protobuf string in other scripting languages.
* "data" (bytes): file data, used when sending a direct file request
* "location" (map<string, string>): location details, used when sending a remote file request ("data" takes precedence over this key)
* "filename" (string): filename of the file represented in the request
* "source" (string): source of the file request (e.g. system hostname)
* "flavors" (repeated string): flavor of the file represented in the request
* "metadata" (map<string, string>): metadata associated with the file request

## Scanners
Each scanner parses files of a specific flavor and performs metadata collection and/or file extraction on them. Scanners are typically named after the type of file they are intended to scan (e.g. "ScanHtml", "ScanPe", "ScanRar") but may also be named after the type of function or tool they use to perform their tasks (e.g. "ScanExiftool", "ScanHeader", "ScanOcr").

### Scanner List
The table below describes each scanner and its options. Each scanner has the hidden option "scanner_timeout" which can override the distribution scanner_timeout.

| Scanner Name | Scanner Description | Scanner Options |
|--------------|---------------------|-----------------|
| ScanAntiword | Extracts text from MS Word documents | "tempfile_directory" -- location where tempfile writes temporary files (defaults to "/tmp/") |
| ScanBatch | Collects metadata from batch script files | N/A |
| ScanBzip2 | Decompresses bzip2 files | N/A |
| ScanCuckoo | Sends files to a Cuckoo sandbox | "url" -- URL of the Cuckoo sandbox (defaults to None)<br>"priority" -- Cuckoo priority assigned to the task (defaults to 3)<br>"timeout" -- amount of time (in seconds) to wait for the task to upload (defaults to 10)<br>"unique" -- boolean that tells Cuckoo to only analyze samples that have not been analyzed before (defaults to True)<br>"username" -- username used for authenticating to Cuckoo (defaults to None, optionally read from environment variable "CUCKOO_USERNAME")<br>"password" -- password used for authenticating to Cuckoo (defaults to None, optionally read from environment variable "CUCKOO_PASSWORD") |
| ScanDocx | Collects metadata and extracts text from docx files | "extract_text" -- boolean that determines if document text should be extracted as a child file (defaults to False) |
| ScanElf | Collects metadata from ELF files | N/A |
| ScanEmail | Collects metadata and extract files from email messages | N/A |
| ScanEntropy | Calculates entropy of files | N/A |
| ScanExiftool | Collects metadata parsed by Exiftool | "tempfile_directory" -- location where tempfile writes temporary files (defaults to "/tmp/") |
| ScanFalconSandbox | Sends files to an instance of Falcon Sandbox | "server" -- URL of the Falcon Sandbox API inteface <br>"priority" -- Falcon Sandbox priority assigned to the task (defaults to 3)<br>"timeout" -- amount of time (in seconds) to wait for the task to upload (defaults to 60)<br>"envID" -- list of numeric envrionment IDs that tells Falcon Sandbox which sandbox to submit a sample to (defaults to [100])<br>"api_key" -- API key used for authenticating to Falcon Sandbox (defaults to None, optionally read from environment variable "FS_API_KEY")<br>"api_secret" --  API secret key used for authenticating to Falcon Sandbox (defaults to None, optionally read from environment variable "FS_API_SECKEY") |
| ScanGif | Extracts data embedded in GIF files | N/A |
| ScanGzip | Decompresses gzip files | N/A
| ScanHash | Calculates file hash values | N/A |
| ScanHeader | Collects file header | "length" -- number of header characters to log as metadata (defaults to 50) |
| ScanHtml | Collects metadata and extracts embedded files from HTML files | "parser" -- sets the HTML parser used during scanning (defaults to "html.parser") |
| ScanJarManifest | Collects metadata from JAR manifest files | N/A |
| ScanJavascript | Collects metadata from Javascript files | "beautify" -- deobfuscates JavaScript before parsing (defaults to True) |
| ScanJpeg | Extracts data embedded in JPEG files | N/A |
| ScanJson | Collects keys from JSON files | N/A |
| ScanLibarchive | Extracts files from libarchive-compatible archives. | "limit" -- maximum number of files to extract (defaults to 1000) |
| ScanLzma | Decompresses lzma files | N/A |
| ScanMacho | Collects metadata from Mach-O files | "tempfile_directory" -- location where tempfile writes temporary files (defaults to "/tmp/") |
| ScanMmbot | Collects VB results from a server running mmbotd | "server" -- network address and network port of the mmbotd server (defaults to "127.0.0.1:33907")<br>"timeout" -- amount of time (in milliseconds) to wait for a response from the server (defaults to 10000) |
| ScanOcr | Collects metadata and extracts optical text from image files | "extract_text" -- boolean that determines if document text should be extracted as a child file (defaults to False)<br>"tempfile_directory" -- location where `tempfile` will write temporary files (defaults to "/tmp/") |
| ScanOle | Extracts files from OLECF files | N/A |
| ScanPdf | Collects metadata and extracts streams from PDF files | "extract_text" -- boolean that determines if document text should be extracted as a child file (defaults to False)<br>"limit" -- maximum number of files to extract (defaults to 2000) |
| ScanPe | Collects metadata from PE files | N/A |
| ScanPgp | Collects metadata from PGP files | N/A |
| ScanPhp | Collects metadata from PHP files | N/A |
| ScanPkcs7 | Extracts files from PKCS7 certificate files | N/A |
| ScanRar | Extracts files from RAR archives | "limit" -- maximum number of files to extract (defaults to 1000) |
| ScanRpm | Collects metadata and extracts files from RPM files | "tempfile_directory" -- location where `tempfile` will write temporary files (defaults to "/tmp/") |
| ScanRtf | Extracts embedded files from RTF files | "limit" -- maximum number of files to extract (defaults to 1000) |
| ScanSelf | Collects metadata from the file's internal attributes | N/A |
| ScanStrings | Collects strings from file data | "limit" -- maximum number of strings to collect, starting from the beginning of the file (defaults to 0, collects all strings) |
| ScanSwf | Decompresses swf (Flash) files | N/A |
| ScanTar | Extract files from tar archives | "limit" -- maximum number of files to extract (defaults to 1000) |
| ScanTnef | Collects metadata and extract files from TNEF files | N/A |
| ScanUpx | Decompresses UPX packed files | "tempfile_directory" -- location where `tempfile` will write temporary files (defaults to "/tmp/") |
| ScanUrl | Collects URLs from files | "regex" -- dictionary entry that establishes the regular expression pattern used for URL parsing (defaults to a widely scoped regex) |
| ScanVb | Collects metadata from Visual Basic script files | N/A |
| ScanVba | Extracts and analyzes VBA from document files | "analyze_macros" -- boolean that determines if macros should be analyzed (defaults to True) |
| ScanX509 | Collects metadata from x509 and CRL files | "type" -- string that determines the type of x509 certificate being scanned (no default, assigned as either "der" or "pem" depending on flavor) |
| ScanXml | Log metadata and extract files from XML files | "extract_tags" -- list of XML tags that will have their text extracted as child files (defaults to empty list)<br>"metadata_tags" -- list of XML tags that will have their text logged as metadata (defaults to empty list) |
| ScanYara | Scans files with YARA rules | "location" -- location of the YARA rules file or directory (defaults to "/etc/yara/")<br>"metadata_identifiers" -- list of YARA rule metadata identifiers (e.g. "Author") that should be logged as metadata (defaults to empty list) |
| ScanZip | Extracts files from zip archives | "limit" -- maximum number of files to extract (defaults to 1000) |

## Use Cases
Below are some select use cases that show the value Strelka can add to a threat detection tech stack. Keep in mind that these results are parsed in real time without post-processing and are typically correlated with other detection/response tools (e.g. Bro, Volatility, etc.). The file metadata shown below was derived from files found in [VirusShare](https://virusshare.com/) torrent no. 323 and from a test file in the [MaliciousMacroBot (MMBot) repository](https://github.com/egaus/MaliciousMacroBot).

### Extracting child files
Strelka scanners can decompress and unarchive child files from a wide variety of common file formats, including gzip, ISO, RAR, tar, and ZIP. Child files can also be extracted from files that are not typically thought of as file containers, including MZ, HTML, and XML. Child files are recursively scanned by the system and retain their relationship to parent files via unique identifiers (`uid`, `parent_uid`, and `root_uid`).

Below is a partial scan result for a ZIP file that contains DLLs, MZ, and text files -- this shows which scanner extracted the child files and the order in which Strelka extracted them.
```json
"VirusShare_f87a71c7cda125599756a7440eac869d"
"ScanZip::ImeHook.dll"
"ScanPe::digital_signature"
"ScanPkcs7::serial_number_161681096793302212950385451611660389869"
"ScanPkcs7::serial_number_95367435335131489231313444090147582372"
"ScanPkcs7::serial_number_35937092757358589497111621496656664184"
"ScanPkcs7::serial_number_458292208492782643314715"
"ScanPkcs7::serial_number_43358040091624116037328344820021165185"
"ScanPkcs7::serial_number_109001353806506068745144901449045193671"
"ScanZip::ImeHook.ime"
"ScanPe::digital_signature"
"ScanPkcs7::serial_number_161681096793302212950385451611660389869"
"ScanPkcs7::serial_number_95367435335131489231313444090147582372"
"ScanPkcs7::serial_number_35937092757358589497111621496656664184"
"ScanPkcs7::serial_number_43358040091624116037328344820021165185"
"ScanPkcs7::serial_number_109001353806506068745144901449045193671"
"ScanZip::ImeLoadDll.dll"
"ScanPe::digital_signature"
"ScanPkcs7::serial_number_161681096793302212950385451611660389869"
"ScanPkcs7::serial_number_95367435335131489231313444090147582372"
"ScanPkcs7::serial_number_35937092757358589497111621496656664184"
"ScanPkcs7::serial_number_458292208492782643314715"
"ScanPkcs7::serial_number_43358040091624116037328344820021165185"
"ScanPkcs7::serial_number_109001353806506068745144901449045193671"
"ScanZip::QQXW_sync.dll"
"ScanPe::digital_signature"
"ScanPkcs7::serial_number_161681096793302212950385451611660389869"
"ScanPkcs7::serial_number_95367435335131489231313444090147582372"
"ScanPkcs7::serial_number_35937092757358589497111621496656664184"
"ScanPkcs7::serial_number_43358040091624116037328344820021165185"
"ScanPkcs7::serial_number_109001353806506068745144901449045193671"
"ScanZip::QQXuanWUSyncTool.exe"
"ScanZip::Sync.ini"
"ScanZip::_QQXuanWUSyncTool.exe"
"ScanPe::digital_signature"
"ScanPkcs7::serial_number_161681096793302212950385451611660389869"
"ScanPkcs7::serial_number_95367435335131489231313444090147582372"
"ScanPkcs7::serial_number_35937092757358589497111621496656664184"
"ScanPkcs7::serial_number_43358040091624116037328344820021165185"
"ScanPkcs7::serial_number_109001353806506068745144901449045193671"
"ScanZip::bbxcomm.dll"
"ScanPe::digital_signature"
"ScanPkcs7::serial_number_161681096793302212950385451611660389869"
"ScanPkcs7::serial_number_95367435335131489231313444090147582372"
"ScanPkcs7::serial_number_35937092757358589497111621496656664184"
"ScanPkcs7::serial_number_43358040091624116037328344820021165185"
"ScanPkcs7::serial_number_109001353806506068745144901449045193671"
"ScanZip::msvcr90.dll"
"ScanPe::digital_signature"
"ScanPkcs7::serial_number_3914548144742538765706922673626944"
"ScanPkcs7::serial_number_3914548144742538765706922673626944"
"ScanPkcs7::serial_number_220384538441259235003328"
"ScanPkcs7::serial_number_458354918584318987075587"
"ScanPkcs7::serial_number_458441701260288556269574"
"ScanPkcs7::serial_number_458441701260288556269574"
"ScanPkcs7::serial_number_140958392345760462733112971764596107170"
"ScanZip::ver.ini"
"ScanZip::╣ñ╛▀╜Θ╔▄.txt"
```

### Identifying malicious scripts
Strelka supports scanning some of the most common types of malicious script files (JavaScript, VBScript, etc.). Not only are these scripts parsed, but they are also extracted out of relevant parent files -- for example, JavaScript and VBScript can be extracted out of HTML files and VBA code can be extracted out of OLE files.

Below is a partial scan result for an HTML file that contains a malicious VBScript file that contains an encoded Windows executable file. HTML hyperlinks are redacted to prevent accidental navigation.
```json
{
  "self_metadata": {
    "filename": "VirusShare_af8188122b7580b8907c76352d565616",
    "depth": 0,
    "uid": "7b9b9460-7943-4f9b-b7e0-c48653a1adbd",
    "root_uid": "7b9b9460-7943-4f9b-b7e0-c48653a1adbd",
    "hash": "5f0eb1981ed21ad22f67014b8c78ca1f164dfbc27d6bfe66d49c70644202321e",
    "root_hash": "5f0eb1981ed21ad22f67014b8c78ca1f164dfbc27d6bfe66d49c70644202321e",
    "source": "linuxkit-025000000001",
    "scanner_list": [
      "ScanSelf",
      "ScanYara",
      "ScanHash",
      "ScanEntropy",
      "ScanHeader",
      "ScanHtml"
    ],
    "size": 472513
  },
  "hash_metadata": {
    "md5": "af8188122b7580b8907c76352d565616",
    "sha1": "2a9eef195a911c966c4130223a64f7f47d6f8b8f",
    "sha256": "5f0eb1981ed21ad22f67014b8c78ca1f164dfbc27d6bfe66d49c70644202321e",
    "ssdeep": "6144:SCsMYod+X3oI+YUsMYod+X3oI+YlsMYod+X3oI+YLsMYod+X3oI+YQ:P5d+X3o5d+X3j5d+X315d+X3+"
  },
  "entropy_metadata": {
    "entropy": 4.335250015702422
  },
  "header_metadata": {
    "header": "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Trans"
  },
  "html_metadata": {
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
  },
  "flavors": {
    "yara": [
      "html_file"
    ],
    "mime": [
      "text/html"
    ]
  }
},
{
  "self_metadata": {
    "filename": "ScanHtml::script_5",
    "depth": 1,
    "uid": "153e9833-3d47-4a4d-a098-41efcc6f799e",
    "parent_uid": "7b9b9460-7943-4f9b-b7e0-c48653a1adbd",
    "root_uid": "7b9b9460-7943-4f9b-b7e0-c48653a1adbd",
    "hash": "5a07bc83f2de5cbf28fdeb25a792c41686998118c77ee45a9bb94072ab18a170",
    "parent_hash": "5f0eb1981ed21ad22f67014b8c78ca1f164dfbc27d6bfe66d49c70644202321e",
    "root_hash": "5f0eb1981ed21ad22f67014b8c78ca1f164dfbc27d6bfe66d49c70644202321e",
    "source": "ScanHtml",
    "scanner_list": [
      "ScanSelf",
      "ScanYara",
      "ScanHash",
      "ScanEntropy",
      "ScanHeader",
      "ScanVb",
      "ScanUrl"
    ],
    "size": 113073
  },
  "hash_metadata": {
    "md5": "64659f52fd89e89171af1f7d9441f2f2",
    "sha1": "763b46a4493e413f74e25b191c553a504e1ce66b",
    "sha256": "5a07bc83f2de5cbf28fdeb25a792c41686998118c77ee45a9bb94072ab18a170",
    "ssdeep": "1536:cyLi+rffMxqNisaQx4V5roEIfGJZN8qbV76EX1UP09weXA3oJrusBTOy9dGCsQSz:cyfkMY+BES09JXAnyrZalI+YG"
  },
  "entropy_metadata": {
    "entropy": 4.0084789402784775
  },
  "header_metadata": {
    "header": "<!--\nDropFileName = \"svchost.exe\"\nWriteData = \"4D5"
  },
  "vb_metadata": {
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
  },
  "flavors": {
    "mime": [
      "text/plain"
    ],
    "external": [
      "vbscript"
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
  "uid": "eaf645d6-bd61-4522-821f-6fadb71512a4",
  "root_uid": "eaf645d6-bd61-4522-821f-6fadb71512a4",
  "hash": "5face75de37c69e6bf496acb48c0907cbb0d12caaa42386035efc56a10f952f3",
  "root_hash": "5face75de37c69e6bf496acb48c0907cbb0d12caaa42386035efc56a10f952f3",
  "source": "linuxkit-025000000001",
  "scanner_list": [
    "ScanSelf",
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
  "self_metadata": {
    "filename": "VirusShare_1860271b6d530f8e120637f8248e8c88",
    "depth": 0,
    "uid": "c65e5d0a-3a7d-4747-93bd-7d02cb68e164",
    "root_uid": "c65e5d0a-3a7d-4747-93bd-7d02cb68e164",
    "hash": "779e4ae1ac987b1be582b8f33a300564f6b3a3410641e27752d35f61055bbc4f",
    "root_hash": "779e4ae1ac987b1be582b8f33a300564f6b3a3410641e27752d35f61055bbc4f",
    "source": "linuxkit-025000000001",
    "scanner_list": [
      "ScanSelf",
      "ScanYara",
      "ScanHash",
      "ScanEntropy",
      "ScanHeader",
      "ScanUrl"
    ],
    "size": 1856
  },
  "hash_metadata": {
    "md5": "1860271b6d530f8e120637f8248e8c88",
    "sha1": "ca5aaae089a21dea271a4a5f436589492615eac9",
    "sha256": "779e4ae1ac987b1be582b8f33a300564f6b3a3410641e27752d35f61055bbc4f",
    "ssdeep": "24:cCEDx8CPP9C7graWH0CdCBrCkxcCLlACCyzECDxHCfCqyCM:g9LPnPWesnV"
  },
  "entropy_metadata": {
    "entropy": 4.563745722228093
  },
  "header_metadata": {
    "header": "cd /tmp || cd /var/run || cd /mnt || cd /root || c"
  },
  "url_metadata": {
    "urls": [
      "[redacted]"
    ]
  },
  "flavors": {
    "mime": [
      "text/plain"
    ]
  }
}
```

### Interacting with external systems
At release, Strelka supports sending files to a Cuckoo sandbox and sending VBScript files to a networked instance of MMBot.

Below is a partial scan result for a document file that contains VBA/VBScript, this shows the maliciousness prediction and metadata retrieved from MMBot.
```json
{
  "filename": "/samples/benign.xlsm",
  "depth": 0,
  "uid": "12db8e8b-cfea-4290-85e0-8314ec00289f",
  "root_uid": "12db8e8b-cfea-4290-85e0-8314ec00289f",
  "hash": "19f6d017bb49280e0cfb048f2c8692a7ed6290b567a00ab4f2af40da9c104871",
  "root_hash": "19f6d017bb49280e0cfb048f2c8692a7ed6290b567a00ab4f2af40da9c104871",
  "source": "linuxkit-025000000001",
  "scanner_list": [
    "ScanSelf",
    "ScanYara",
    "ScanHash",
    "ScanEntropy",
    "ScanHeader",
    "ScanExiftool",
    "ScanZip"
  ],
  "size": 10906
},
{
  "self_metadata": {
    "filename": "ScanVba::ThisWorkbook.cls",
    "depth": 2,
    "uid": "c32ae623-9f48-4d0e-ac48-2ca68770863c",
    "parent_uid": "13cb69ec-c7ce-433d-bd2e-14ebbfee1e3f",
    "root_uid": "12db8e8b-cfea-4290-85e0-8314ec00289f",
    "hash": "14de0425a62586687c3d59b7d3d7dc60268f989ab7e07a61403525064d98502a",
    "parent_hash": "8acef9035ae312c851f69f1cb895dfb5f987b6104cef0c0a670e69a6a678f260",
    "root_hash": "19f6d017bb49280e0cfb048f2c8692a7ed6290b567a00ab4f2af40da9c104871",
    "source": "ScanVba",
    "scanner_list": [
      "ScanSelf",
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
  "hash_metadata": {
    "md5": "b59c5dbc9757e748ff31c4ef3478af98",
    "sha1": "4a864f065b59cd4ebe031f2cbc70aecd5331a2de",
    "sha256": "14de0425a62586687c3d59b7d3d7dc60268f989ab7e07a61403525064d98502a",
    "ssdeep": "6:YhH0shm7FWSvVG/4H3HcM25E3YRV3opedT1Xdv8SAFYDsoS:Y7gZWaVW4B25dTJaoS"
  },
  "entropy_metadata": {
    "entropy": 4.838185555972263
  },
  "header_metadata": {
    "header": "Attribute VB_Name = \"ThisWorkbook\"\r\nAttribute VB_B"
  },
  "vb_metadata": {
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
  "mmbot_metadata": {
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
  "flags": [
    "ScanYara::compiling_error"
  ],
  "flavors": {
    "yara": [
      "vb_file"
    ],
    "mime": [
      "text/plain"
    ]
  }
}
```

## Contributing
Guidelines for contributing can be found [here](https://github.com/target/strelka/blob/master/CONTRIBUTING.md).

## Related Projects
* [Laika BOSS](https://github.com/lmco/laikaboss)
* [File Scanning Framework](https://github.com/EmersonElectricCo/fsf)
* [Assemblyline](https://bitbucket.org/cse-assemblyline/)

## Licensing
Strelka and its associated code is released under the terms of the Apache 2.0 license.
