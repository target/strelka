# ============================
# Build stage
# ============================
FROM golang:1.21.5-alpine AS build
LABEL maintainer="Target Brands, Inc."

RUN apk add --no-cache openssl-dev bash build-base pkgconfig librdkafka librdkafka-dev

# Copy whole Go source tree
WORKDIR /go/src/github.com/target/strelka/
COPY ./src/go/ ./src/go/
COPY go.* .

# Make sure go modules ready
RUN go mod download
RUN go get github.com/google/uuid
# Build new frontend including Kafka ingest
RUN cd src/go/cmd/strelka-frontend && \
    CGO_ENABLED=1 go build -tags musl -o /tmp/strelka-frontend .

# ============================
# Runtime Stage
# ============================
FROM alpine
LABEL maintainer="Target Brands, Inc."

RUN apk add --no-cache librdkafka

# Copy compiled binary
COPY --from=build /tmp/strelka-frontend /usr/local/bin/strelka-frontend

# Logging directory
RUN mkdir -p /var/log/strelka && \
    chmod -R 777 /var/log/strelka

# Blank log file for watcher fallback
RUN touch /var/log/strelka/strelka.log

# Expose frontend port
EXPOSE 57314

# ENV variables for Kafka ingest
ENV KAFKA_BOOTSTRAP=kafka:29092
ENV RAW_TOPIC=raw
ENV ANALYSIS_TOPIC=analysis

# Start the Kafka-enabled frontend
ENTRYPOINT ["strelka-frontend","-locallog=true","-kafkalog=true"]
