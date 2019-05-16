FROM golang AS build
LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-filestream/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-filestream .

FROM alpine
COPY --from=build /tmp/strelka-filestream /usr/local/bin/strelka-filestream
RUN apk add --no-cache jq
USER 1001
