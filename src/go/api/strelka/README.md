# Introduction
Strelka's frontend exposes **gRPC** endpoints which send and accept messages via **protocol buffers** (*protobufs*). Any changes to those endpoints or the messages used by the endpoints must be made using a multi-step process. First, the definitions must be changed in `strelka.proto`. Then those definitions will need to be compiled into a usable format so that they can be seamlessly integrated into the Golang application.

Corresponding changes will need to be defined and compiled on the client that communicates with Strelka's gRPC endpoints.

To learn more about gRPC and protobufs, see the following documentation:
- [Introduction to gRPC](https://grpc.io/docs/what-is-grpc/introduction/)
- [Protocol Buffers - Overview](https://developers.google.com/protocol-buffers/docs/overview)
- [Go - Quick start](https://grpc.io/docs/languages/go/quickstart/)

## Compiling Protobufs

To update the protobuf message definitions and/or gRPC endpoints, you must compile them to generate `strelka.pb.go` and `strelka_grpc.pb.go`, which will export definitions that can be used by Go. To do this, follow the steps below:

1. Update defs in `strelka.proto`
2. `go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28`
3. `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2`
4. `export PATH="$PATH:$(go env GOPATH)/bin"`
5. `cd src/go/api/strelka` (if not already there)
6. `protoc --go_out=. --go-grpc_opt=require_unimplemented_servers=false
 --go-grpc_out=. --proto_path=. ./strelka.proto`
7. `cp github.com/sublime-security/strelka/src/go/api/strelka/strelka*.go .`
8. `rm -rf ./github.com`
9. `git status` (you should see that `strelka.pb.go` and `strelka_grpc.pb.go` have been updated)
10. Perform equivalent process on the client that will be communicating with Strelka to send the appropriate messages.
