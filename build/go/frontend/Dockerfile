# Strelka Frontend
# The frontend for a cluster in which clients can connect directly via Envoy.
# For more information, please see: https://target.github.io/strelka/#/?id=strelka-frontend
FROM golang:1.21.5-alpine AS build
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

RUN apk add openssl-dev bash build-base pkgconfig librdkafka librdkafka-dev

# Copy source files and set the working directory
COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
WORKDIR /go/src/github.com/target/strelka/src/go/
COPY go.* /go/src/github.com/target/strelka/

# Statically compile and output to tmp
RUN go mod download && \
    CGO_ENABLED=1 go build -tags musl -o /tmp/strelka-frontend cmd/strelka-frontend/main.go

# Initialize runtime container
FROM alpine
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

RUN apk add librdkafka

# Copy binary
COPY --from=build /tmp/strelka-frontend /usr/local/bin/strelka-frontend
COPY --from=build  /usr/local/lib/ /usr/local/lib/

# Create logging directory
RUN mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/

#Create blank strelka.log file to make sure watcher has something to start with
RUN touch /var/log/strelka/strelka.log
RUN chmod -R 777 /var/log/strelka/strelka.log

# Set container entrypoint. This could be set/overridden elsewhere in deployment (e.g. k8s, docker-compose, etc.)
# Currently overwritten in ./build/docker-compose.yml
ENTRYPOINT ["strelka-frontend", "-locallog=true", "-kafkalog=false"]
