# mmrpc container is based on Ubuntu Bionic LTS
# needs cleanup
FROM ubuntu:18.04

LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Copy Strelka files
COPY . /strelka/

# Update packages
RUN apt-get -qq update && \
    apt-get install --no-install-recommends -qq \
# Install build packages
    git \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel && \
# Install Python packages
    pip3 install -r /strelka/docker/mmrpc/requirements.txt && \
# Compile protobuf
    cd /strelka/ && \
    python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. strelka/proto/strelka.proto && \
    python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. strelka/proto/mmbot.proto && \
# Install Strelka
    cd /strelka/ && \
    mv docker/mmrpc/setup.py /strelka/ && \
    python3 setup.py -q build && \
    python3 setup.py -q install && \
    python3 setup.py -q clean --all && \
# Remove build packages
    python3 setup.py -q clean --all && \
    rm -rf dist/ strelka.egg-info && \
    pip3 uninstall -y grpcio-tools && \
    apt-get autoremove -qq --purge \
    git \
    python3-dev \
    python3-pip \
    python3-wheel && \
    apt-get purge -qq python3-setuptools  && \
    apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/* /strelka/
USER 1001
