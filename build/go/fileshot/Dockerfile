FROM golang AS build
LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-fileshot/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-fileshot .

FROM alpine
COPY --from=build /tmp/strelka-fileshot /usr/local/bin/strelka-fileshot
RUN apk add --no-cache jq
USER 1001
