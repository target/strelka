package main

import (
        "context"
        "flag"
        "fmt"
        "io"
        "io/ioutil"
        "log"
        "net"
        "time"
        "encoding/json"

        "google.golang.org/grpc"
        "github.com/go-redis/redis"
        "github.com/google/uuid"
        "gopkg.in/yaml.v2"

        "github.com/target/strelka/src/go/api/health"
        "github.com/target/strelka/src/go/api/strelka"
        "github.com/target/strelka/src/go/pkg/rpc"
        "github.com/target/strelka/src/go/pkg/structs"
)

type server struct{
        cache           *redis.Client
        coordinator     *redis.Client
        responses       chan <- *strelka.ScanResponse
}

type request struct {
        Id          string                  `json:"id,omitempty"`
        Client      string                  `json:"client,omitempty"`
        Source      string                  `json:"source,omitempty"`
        Attributes  *strelka.Attributes     `json:"attributes,omitempty"`
}

func (s *server) Check(ctx context.Context, req *health.HealthCheckRequest) (*health.HealthCheckResponse, error) {
        return &health.HealthCheckResponse{
            Status: health.HealthCheckResponse_SERVING,
        }, nil
}

func (s *server) ScanFile(stream strelka.Frontend_ScanFileServer) error {
        deadline, ok := stream.Context().Deadline()
        if ok == false {
                return nil
        }

        id := uuid.New().String()
        var inReq *strelka.Request
        var inAttr *strelka.Attributes
        for {
                in, err := stream.Recv()
        		if err == io.EOF {
                        break
        		}
        		if err != nil {
                        fmt.Printf("%v", err)
                        return err
        		}

                if inReq == nil {
                        inReq = in.Request
                }
                if inAttr == nil {
                        inAttr = in.Attributes
                }

                s.cache.RPush(id, in.Data)
    	}
        s.cache.ExpireAt(id, deadline)

        err := s.coordinator.ZAdd(
                "tasks",
                redis.Z{
                        Score:  float64(deadline.Unix()),
                        Member: id,
                },
        ).Err()
        if err != nil {
                return err
        }

        if inReq.Id == "" {
                inReq.Id = id
        }

        r := request{
                Id:inReq.Id,
                Client:inReq.Client,
                Source:inReq.Source,
                Attributes:inAttr,
        }

        for {
                lpop, err := s.coordinator.LPop(fmt.Sprintf("evt:%v", id)).Result()
                if err != nil {
                        time.Sleep(250 * time.Millisecond)
                        continue
                }
                if lpop == "FIN" {
                        break
                }

                m := make(map[string]interface{})
                m["time"] = time.Now().Format(time.RFC3339)
                m["request_metadata"] = r
                if err := json.Unmarshal([]byte(lpop), &m); err != nil{
                        return err
                }
                o, _ := json.Marshal(m)

                resp := &strelka.ScanResponse{
                        Id:inReq.Id,
                        Event:string(o),
                }
                s.responses <- resp
                if err := stream.Send(resp); err != nil {
                        return err
                }
        }

        return nil
}

func main() {
    confPath := flag.String(
            "c",
            "/etc/strelka/frontend.yaml",
            "path to frontend config")
    flag.Parse()

    confData, err := ioutil.ReadFile(*confPath)
    if err != nil {
            log.Fatalf("failed to read config file %s: %v", confPath, err)
    }
    var conf structs.Frontend
    err = yaml.Unmarshal(confData, &conf)
    if err != nil {
            log.Fatalf("failed to load config data: %v", err)
    }

    listen, err := net.Listen("tcp", conf.Server)
	if err != nil {
            log.Fatalf("failed to listen: %v", err)
	}

    responses := make(chan *strelka.ScanResponse, 100)
    defer close(responses)
    // this should become an option -- choose the type of response handler and options
    go rpc.LogResponses(responses, conf.Log)

    cache := redis.NewClient(&redis.Options{
            Addr:       conf.Cache.Addr,
            DB:         conf.Cache.Db,
    })
    err = cache.Ping().Err()
    if err != nil {
            log.Fatalf("failed to connect to cache: %v", err)
    }
    coordinator := redis.NewClient(&redis.Options{
            Addr:       conf.Coordinator.Addr,
            DB:         conf.Coordinator.Db,
    })
    err = coordinator.Ping().Err()
    if err != nil {
            log.Fatalf("failed to connect to coordinator: %v", err)
    }

	s := grpc.NewServer()
    opts := &server{
            cache:cache,
            coordinator:coordinator,
            responses:responses,
    }
	strelka.RegisterFrontendServer(s, opts)
    health.RegisterHealthServer(s, opts)
	s.Serve(listen)
}
