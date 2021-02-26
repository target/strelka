FROM golang AS build
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Copy source files and set the working directory
COPY ./src/go/ /go/src/github.com/target/strelka/src/go/
WORKDIR /go/src/github.com/target/strelka/src/go/

# Initialize, get, and build go modules and main package
RUN go mod init && \
    go mod tidy && \
    cd /go/src/github.com/target/strelka/src/go/cmd/strelka-oneshot/ && \
    CGO_ENABLED=0 go build -o /tmp/strelka-oneshot .

# Move build and initialize non-root user
FROM alpine
COPY --from=build /tmp/strelka-oneshot /usr/local/bin/strelka-oneshot
RUN apk add --no-cache jq
USER 1001
