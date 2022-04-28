# Strelka Manager
# Manages portions of Strelka's Redis database.
# For more information, please see: https://target.github.io/strelka/#/?id=strelka-manager
FROM golang:1.17.6 AS build
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Copy source files and set the working directory
COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
WORKDIR /go/src/github.com/target/strelka/src/go/cmd/strelka-manager

# Statically compile and output to /tmp
RUN go mod download && \
    CGO_ENABLED=0 go build -o /tmp/strelka-manager .

# Initialize runtime container with non-root user
FROM alpine
USER 1001
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Copy binary to /usr/local/bin
COPY --from=build /tmp/strelka-manager /usr/local/bin/strelka-manager

# Set container entrypoint. This could be set/overridden elsewhere in deployment (e.g. k8s, docker-compose, etc.)
# Currently overwritten in ./build/docker-compose.yml
ENTRYPOINT ["strelka-manager"]
