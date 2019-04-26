FROM golang AS build
LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-redis/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-redis .

FROM alpine
COPY --from=build /tmp/strelka-redis /usr/local/bin/strelka-redis
USER 1001
