# Strelka Oneshot
# Client is designed to be used to submit a single file from command line and receive the result for it immediately.
# For more information, please see: https://target.github.io/strelka/#/?id=strelka-oneshot
FROM golang:1.17.6 AS build
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Copy source files and set the working directory
COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
WORKDIR /go/src/github.com/target/strelka/src/go/cmd/strelka-oneshot

# Statically compile and output to tmp
RUN go mod download && \
    CGO_ENABLED=0 go build -o /tmp/strelka-oneshot .

# Initialize runtime container
FROM alpine
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Copy binary
COPY --from=build /tmp/strelka-oneshot /usr/local/bin/strelka-oneshot

# Install jq
RUN apk add --no-cache jq

# Initialize with non-root user
USER 1001

# Set container entrypoint. This could be set/overridden elsewhere in deployment (e.g. k8s, docker-compose, etc.)
# Currently overwritten in ./build/docker-compose.yml
ENTRYPOINT ["strelka-oneshot"]
