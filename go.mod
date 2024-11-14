module strelka-frontend

go 1.22.9

require (
	github.com/go-redis/redis/v8 v8.11.4
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0
	github.com/target/strelka v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.68.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
)

replace github.com/target/strelka => ./
