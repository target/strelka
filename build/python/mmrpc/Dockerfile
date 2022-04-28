FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Update packages
RUN apt-get -qq update && \
    apt-get install --no-install-recommends -qq \
# Install build packages
    build-essential \
    git \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel

#Install Strelka Requirements
COPY ./build/python/mmrpc/requirements.txt /strelka/requirements.txt
RUN pip3 install --no-cache-dir -r /strelka/requirements.txt

COPY ./src/python/ /strelka/
COPY ./build/python/mmrpc/setup.py /strelka/setup.py

# Install Strelka
RUN cd /strelka/ && \
    python3 setup.py -q build && \
    python3 setup.py -q install && \
# Remove build packages
    python3 setup.py -q clean --all && \
    rm -rf dist/ strelka.egg-info && \
    pip3 uninstall -y grpcio-tools && \
    apt-get autoremove -qq --purge \
    build-essential \
    git \
    python3-dev \
    python3-pip \
    python3-wheel && \
    apt-get purge -qq python3-setuptools  && \
    apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/* /strelka/

USER 1001
