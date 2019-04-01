# Strelka container is based on Ubuntu Bionic LTS
FROM ubuntu:18.04

LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

ARG YARA_VERSION=3.9.0
ARG YARA_PYTHON_VERSION=3.9.0

# Copy Strelka files
COPY . /usr/local/src/strelka/

# Update packages
RUN apt-get -qq update && \
    apt-get install --no-install-recommends -qq \
# Install build packages
    automake \
    build-essential \
    curl \
    gcc \
    git \
    libtool \
    make \
    python3-dev \
    python3-pip \
    python3-wheel \
# Install runtime packages
    antiword \
    libarchive-dev \
    libfuzzy-dev \
    libimage-exiftool-perl \
    libmagic-dev \
    libssl-dev \
    python3-setuptools \
    redis-server \
    tesseract-ocr \
    unrar \
    upx \
    jq && \
# Install Python packages
    pip3 install -r /usr/local/src/strelka/docker/strelka-backend/requirements.txt && \
# Compile protobuf
    cd /usr/local/src/strelka/ && \
    python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. strelka/proto/strelka.proto && \
    python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. strelka/proto/mmbot.proto && \
# Install YARA
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz && \
    tar -zxvf v$YARA_VERSION.tar.gz && \
    cd yara-$YARA_VERSION/ && \
    ./bootstrap.sh && \
    ./configure --with-crypto --enable-dotnet --enable-magic && \
    make && make install && make check && \
# Install yara-python
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara-python/archive/v$YARA_PYTHON_VERSION.tar.gz && \
    tar -zxvf v$YARA_PYTHON_VERSION.tar.gz && \
    cd yara-python-$YARA_PYTHON_VERSION/ && \
    python3 setup.py build --dynamic-linking && \
    python3 setup.py install && \
# Install Strelka
    cd /usr/local/src/strelka/ && \
    mv docker/strelka-backend/setup.py /usr/local/src/strelka/ && \
    python3 setup.py -q build && \
    python3 setup.py -q install && \
# Remove build packages
    python3 setup.py -q clean --all && \
    rm -rf dist/ strelka.egg-info && \
    pip3 uninstall -y grpcio-tools && \
    apt-get autoremove -qq --purge \
    automake \
    build-essential \
    curl \
    gcc \
    git \
    libtool \
    make \
    python3-dev \
    python3-pip \
    python3-wheel && \
    apt-get purge -qq python3-setuptools  && \
    apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/* /usr/local/src/strelka/ /tmp/yara* && \
# Assign permissions to Strelka scan result logging directory
    mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/
USER 1001
