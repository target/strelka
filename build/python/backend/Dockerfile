FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive
LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

ARG YARA_VERSION=3.11.0
ARG YARA_PYTHON_VERSION=3.11.0
ARG CAPA_VERSION=1.1.0

# Copy Strelka files
COPY ./src/python/ /strelka/
COPY ./build/python/backend/requirements.txt /strelka/requirements.txt
COPY ./build/python/backend/setup.py /strelka/setup.py

# Update packages
RUN apt-get -qq update && \
# Install build packages
    apt-get install --no-install-recommends -qq \
    automake \
    build-essential \
    curl \
    gcc \
    git \
    libtool \
    make \
    swig \
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
# Install FireEye CAPA
#   - Binary installation, not supported as Python 3 plugin
#   - Requires binary to be executable
#   - Vivisect dependency requires available /.viv/ folder.
    cd /tmp/ && \
    curl -OL https://github.com/fireeye/capa/releases/download/v$CAPA_VERSION/capa-linux && \
    chmod +x /tmp/capa-linux && \
    mkdir /.viv/ && \
    chmod -R a+rw /.viv && \
# Install FireEye FLOSS
#   - Binary installation, not supported as Python 3 plugin
#   - Requires binary to be executable
    cd /tmp/ && \
    curl -OL https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss && \
    chmod +x /tmp/floss && \
# Install Python packages
    pip3 install -r /strelka/requirements.txt && \
    pip3 install --index-url https://lief-project.github.io/packages --trusted-host lief.quarkslab.com lief && \
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
    cd /strelka/ && \
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
    rm -rf /var/lib/apt/lists/* /strelka/ /tmp/yara* && \
# Assign permissions to Strelka scan result logging directory
    mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/
USER 1001
