FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

ARG CONFIG_TESTS=false

ARG USERNAME=strelka
ARG USER_UID=1001
ARG USER_GID=$USER_UID

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME

ARG YARA_VERSION=4.2.3
ARG YARA_PYTHON_VERSION=4.2.3
ARG CAPA_VERSION=5.0.0
ARG EXIFTOOL_VERSION=12.52

# Set up package pinning for future releases (kinetic 22.10, 7zip 22.01+dfsg-2)
COPY ./build/python/backend/pin.pref /etc/apt/preferences.d/pin.pref
COPY ./build/python/backend/kinetic.list /etc/apt/sources.list.d/kinetic.list

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install build packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get -qq update && \
    apt-get install -qq -y --no-install-recommends \
    automake \
    build-essential \
    cmake \
    curl \
    gcc \
    git \
    gpg \
    libglu1-mesa \
    libtool \
    make \
    swig \
    python3-dev \
    python3-pip \
    python3-wheel \
    python-is-python3 \
    pkg-config

# Add zeek repo
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get -qq update && \
    apt-get install -qq -y --no-install-recommends \
    7zip \
    antiword \
    binwalk \
    libarchive-dev \
    libcompress-raw-lzma-perl \
    libfuzzy-dev \
    libjansson-dev \
    libmagic-dev \
    libssl-dev \
    libzbar0 \
    libgl1 \
    python3-setuptools \
    redis-server \
    tesseract-ocr \
    unrar \
    unzip \
    upx \
    jq \
    zeek-lts && \
#clean up zeek install
    cp /opt/zeek/bin/zeek /bin/zeek && \
    rm -rf /opt/zeek/share/btest /opt/zeek/bin && \
    rm -rf /opt/zeek/lib/*.a && \
# Download and compile exiftool
    cd /tmp/ && \
    curl -OL https://github.com/exiftool/exiftool/archive/refs/tags/$EXIFTOOL_VERSION.tar.gz && \
    tar -zxvf $EXIFTOOL_VERSION.tar.gz && \
    cd exiftool-$EXIFTOOL_VERSION/ && \
    perl Makefile.PL && \
    make -s && \
    make -s install && \
# Install FireEye CAPA rules and signatures
    mkdir -p /etc/capa/rules/ && \
    curl -OL https://github.com/mandiant/capa-rules/archive/refs/tags/v$CAPA_VERSION.zip && \
    unzip v$CAPA_VERSION.zip -d /etc/capa/rules/ && \
    rm -rf v$CAPA_VERSION.zip && \
    mkdir -p /etc/capa/signatures/ && \
    cd /etc/capa/signatures/ && \
    curl -OL https://github.com/mandiant/capa/raw/master/sigs/1_flare_msvc_rtf_32_64.sig && \
    curl -OL https://github.com/mandiant/capa/raw/master/sigs/2_flare_msvc_atlmfc_32_64.sig && \
    curl -OL https://github.com/mandiant/capa/raw/master/sigs/3_flare_common_libs.sig && \
# Install FireEye FLOSS
#   - Binary installation, not supported as Python 3 plugin
#   - Requires binary to be executable
    cd /tmp/ && \
    curl -OL https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss && \
    chmod +x /tmp/floss && \
    mv /tmp/floss /bin/floss && \
# Install YARA
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz && \
    tar -zxvf v$YARA_VERSION.tar.gz && \
    cd yara-$YARA_VERSION/ && \
    ./bootstrap.sh && \
    ./configure --with-crypto --enable-magic --enable-cuckoo && \
    make -s && make -s install && make -s check && \
# Install yara-python
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara-python/archive/v$YARA_PYTHON_VERSION.tar.gz && \
    tar -zxvf v$YARA_PYTHON_VERSION.tar.gz && \
    cd yara-python-$YARA_PYTHON_VERSION/ && \
    python3 setup.py build --dynamic-linking && \
    python3 setup.py install

# Install JTR
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get install -qq -y --no-install-recommends \
    ca-certificates \
    zlib1g-dev \
    yasm \
    libgmp-dev \
    libpcap-dev \
    libbz2-dev \
    libgomp1 && \
# The maintainer isn't big on releases or tags so grab an arbitrary, but consistent, commit.
# Additionally jump through some extra hoops to get the single commit to save some download time.
    mkdir jtr && cd jtr && git init && git remote add origin https://github.com/openwall/john.git && git fetch --depth 1 origin b5c10480f56ff1b5d76c6cbdaf9c817582ee2228 && git reset --hard FETCH_HEAD \
  && rm -rf /jtr/.git \
  && cd /jtr/src \
  && ./configure \
  && make -s clean \
  && make -sj4 \
  && make -s install \
  && cp -Tr /jtr/run/ /jtr && rm -rf /jtr/run \
  && chmod -R 777 /jtr \
  && chown -R 1001:1001 /jtr

# Copy Strelka files
COPY ./src/python/ /strelka/
COPY ./configs/python/backend/ /etc/strelka/

# Install Python packages
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 -q --disable-pip-version-check install -r /strelka/requirements.txt

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
RUN echo '[+] Run build checks' && \
    cd /strelka/strelka/ && \
    python3 -m pytest -p no:cacheprovider -s tests/ && \
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
