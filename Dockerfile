# Strelka container is based on Ubuntu Bionic LTS
FROM ubuntu:18.04

LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

ENV DEBIAN_FRONTEND=noninteractive

ARG YARA_VERSION=3.8.1
ARG YARA_PYTHON_VERSION=3.8.1
ARG TIMEZONE=UTC

# Copy Strelka files
COPY . /opt/strelka/

# Update packages
RUN apt-get -qq update && \
# Install optional packages and set time zone
    apt-get install -y software-properties-common apt-utils locales tzdata && \
    echo "$TIMEZONE" > /etc/timezone && \
    ln -fs /usr/share/zoneinfo/$TIMEZONE /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get install --no-install-recommends -qq \
# Install build packages
    automake \
    build-essential \
    curl \
    gcc \
    git \
    libtool \
    make \
    protobuf-compiler \
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
    tesseract-ocr \
    unrar \
    upx \
    jq && \
# Install Python packages
    pip3 install -r /opt/strelka/requirements.txt && \
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
# Compile protobuf
    cd /opt/strelka/server/ && \
    protoc --python_out=. strelka.proto && \
# Install Strelka
    cd /opt/strelka/ && \
    python3 setup.py -q build && \
    python3 setup.py -q install && \
    python3 setup.py -q clean --all && \
# Remove build packages
    apt-get autoremove -qq --purge \
    automake \
    build-essential \
    curl \
    gcc \
    git \
    libtool \
    make \
    protobuf-compiler \
    python3-dev \
    python3-pip \
    python3-wheel && \
    apt-get purge -qq python3-setuptools  && \
    apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/* opt/strelka/ /tmp/yara* && \
# Assign permissions to Strelka scan result logging directory
    mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/
USER 1001