# Base and setup configuration
FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# User configuration
ARG CONFIG_TESTS=false

ARG YARA_VERSION=4.5.4
ARG EXIFTOOL_VERSION=12.60

# Environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PYTHONUNBUFFERED 1

# User configuration
ARG USERNAME=strelka
ARG USER_UID=1001
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install build packages
RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
    automake \
    build-essential \
    cmake \
    curl \
    gcc \
    git \
    gpg \
    libffi-dev \
    libglu1-mesa \
    libtool \
    make \
    python3-dev \
    python3-pip \
    swig \
    pkg-config \
    supervisor \
    ncat

# Install Zeek
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
ENV PATH=$PATH:/opt/zeek/bin

# Install runtime packages
RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
    antiword \
    binwalk \
    libarchive-dev \
    libfuzzy-dev \
    libjansson-dev \
    libmagic-mgc \
    libmagic-dev \
    libssl3 \
    libssl-dev \
    libzbar0 \
    libgl1 \
    openssl \
    python3-setuptools \
    redis-server \
    suricata \
    tesseract-ocr \
    unrar \
    unzip \
    upx \
    jq \
    zeek-lts && \
    # Download and compile Archive library (For exiftool)
    cd /tmp/ && \
    curl -OL https://cpan.metacpan.org/authors/id/P/PH/PHRED/Archive-Zip-1.68.tar.gz && \
    tar -xzf Archive-Zip-1.68.tar.gz && \
    cd Archive-Zip-1.68/ && \
    perl Makefile.PL && \
    make && \
    make install && \
    # Download and compile exiftool
    cd /tmp/ && \
    curl -OL https://github.com/exiftool/exiftool/archive/refs/tags/$EXIFTOOL_VERSION.tar.gz && \
    tar -zxvf $EXIFTOOL_VERSION.tar.gz && \
    cd exiftool-$EXIFTOOL_VERSION/ && \
    perl Makefile.PL && \
    make && \
    make install && \
    #Download and move binary for 7z 24.09
    cd /tmp/ && \
    curl -OL https://github.com/ip7z/7zip/releases/download/24.09/7z2409-linux-x64.tar.xz &&\
    tar -xf 7z2409-linux-x64.tar.xz &&\
    cp 7zz /usr/local/bin
    # Install YARA
    RUN cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz && \
    tar -zxvf v$YARA_VERSION.tar.gz && \
    cd yara-$YARA_VERSION/ && \
    ./bootstrap.sh && \
    CC='gcc' CFLAGS='-O0 -fPIC -fno-optimize-sibling-calls' ./configure --with-crypto --enable-magic --enable-cuckoo && \
    make -j1 && make install && \
    # Install yara-python
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara-python/archive/v$YARA_VERSION.tar.gz && \
    tar -zxvf v$YARA_VERSION.tar.gz && \
    cd yara-python-$YARA_VERSION/ && \
    python3 setup.py build --dynamic-linking && \
    python3 setup.py install

# Mark zeek as manual (keeps getting autoremoved?)
RUN apt-mark manual zeek-lts

#Copy Suricata config to default location
COPY configs/python/backend/suricata/suricata.yaml /etc/suricata/suricata.yaml

# Install JTR
RUN apt-get -q update \
    && apt-get install -q -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    zlib1g-dev \
    yasm \
    libgmp-dev \
    libbz2-dev \
    libgomp1 \
    liblzma-dev
RUN cpan Compress::Raw::Lzma

# The maintainer isn't big on releases or tags so grab an arbitrary, but consistent, commit.
# Additionally jump through some extra hoops to get the single commit to save some download time.
RUN mkdir jtr && cd jtr && git init && git remote add origin https://github.com/openwall/john.git && \
    git fetch --depth 1 origin b5c10480f56ff1b5d76c6cbdaf9c817582ee2228 && \
    git reset --hard FETCH_HEAD && \
    rm -rf /jtr/.git && \
    cd /jtr/src && \
    ./configure && \
    make -s clean && \
    make -sj4 && \
    make install && \
    cp -Tr /jtr/run/ /jtr && rm -rf /jtr/run && \
    chmod -R 777 /jtr && \
    chown -R $USER_UID:$USER_UID /jtr

# Install ClamAV
RUN apt-get update -qq && \
    apt-get install -qq -y --no-install-recommends \
    clamav \
    clamav-base \
    clamav-daemon \
    clamav-freshclam

# Update permissions for relevant fresclam log files
RUN touch /var/log/clamav/freshclam.log
RUN chmod 777 /var/log/clamav/freshclam.log
RUN chown clamav /var/log/clamav/freshclam.log
RUN chown 1001:1001 /var/lib/clamav

# Install Poetry globally and copy project files
ENV POETRY_HOME="/opt/poetry"
ENV POETRY_VIRTUALENVS_IN_PROJECT=false
ENV POETRY_NO_INTERACTION=1

# Ensure the poetry bin directory is added to the PATH
ENV PATH="$POETRY_HOME/bin:$PATH"

# Install Poetry using its official installation script
RUN curl -sSL https://install.python-poetry.org | python3 -

# Set the working directory and copy the project files
WORKDIR /strelka/
COPY pyproject.toml poetry.lock ./

# Use Poetry to install the project dependencies globally
# This step is after the COPY step because it is more likely to change,
# and therefore should not be included in earlier layers that can be cached.
RUN pip install --break-system-packages 'ssdeep==3.4' && \
    poetry config virtualenvs.create false && \
    poetry install --only main && \
    rm -rf /root/.cache/pypoetry

# Copy Strelka files
COPY ./src/python/ /strelka/
COPY ./configs/python/backend/ /etc/strelka/

# Install Strelka
RUN cd /strelka/ && \
    python3 setup.py -q build && \
    python3 setup.py -q install && \
# Remove build packages
    python3 setup.py -q clean --all && \
    rm -rf dist/ strelka.egg-info && \
    apt-get purge -y \
    automake \
    build-essential \
    cmake \
    curl \
    gcc \
    git \
    gpg \
    libtool \
    make \
    python3-dev \
    python3-pip \
    python3-wheel && \
    apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/* && \
# Assign permissions to Strelka scan result logging directory
    mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/

# Run tests as non-root user
USER $USERNAME

# Run build checks
# Use --build-arg SCANNER_TEST=test_scan_<scannername>.py to ignore all but selected scanner
# ex: docker-compose build --build-arg SCANNER_TEST=test_scan_yara.py
ARG SCANNER_TEST=""

# Run tests. Fail build if any tests fail.
RUN echo '[+] Run build checks' && \
    cd /strelka/strelka/ && \
    if $SCANNER_TESTS; then python3 -m pytest -p no:cacheprovider -s tests/$SCANNER_TEST; fi && \
    if $CONFIG_TESTS; then python3 -m pytest -s tests_configuration/; fi && \
    echo '[+] Done'

USER root

# Remove build directories and unused files
RUN cd /strelka/ && \
    rm -rf /strelka/ && \
    rm -rf /root/.cache && \
    rm -rf /tmp/*

# Remove config directory (will bind mount once built)
RUN rm -rf /etc/strelka/

USER $USERNAME
