FROM golang AS build
LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
RUN cd /go/src/github.com/target/strelka/src/go/cmd/strelka-frontend/ && \
    go get . && \
    CGO_ENABLED=0 go build -o /tmp/strelka-frontend .

FROM alpine
COPY --from=build /tmp/strelka-frontend /usr/local/bin/strelka-frontend
RUN mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/
USER 1001
