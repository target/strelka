module strelka-frontend

go 1.16

require (
	github.com/go-redis/redis/v8 v8.8.0
	github.com/golang/protobuf v1.4.2
	github.com/google/uuid v1.2.0
	github.com/target/strelka v0.0.0-20211012121236-d9086f35d709
	google.golang.org/grpc v1.36.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/target/strelka => ./