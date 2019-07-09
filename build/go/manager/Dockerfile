FROM golang AS build
LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-manager/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-manager .

FROM alpine
COPY --from=build /tmp/strelka-manager /usr/local/bin/strelka-manager
USER 1001
