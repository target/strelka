package main

import (
        "context"
        "crypto/sha256"
        "encoding/json"
        "flag"
        "fmt"
        "io"
        "io/ioutil"
        "log"
        "net"
        "time"

        "google.golang.org/grpc"
        "github.com/go-redis/redis"
        "github.com/google/uuid"
        "gopkg.in/yaml.v2"

        "github.com/target/strelka/src/go/api/health"
        "github.com/target/strelka/src/go/api/strelka"
        "github.com/target/strelka/src/go/pkg/rpc"
        "github.com/target/strelka/src/go/pkg/structs"
)

type coord struct {
        cli     *redis.Client
}

type gate struct {
        cli     *redis.Client
        ttl     time.Duration
}

type server struct {
        coordinator     coord
        gatekeeper      gate
        responses       chan <- *strelka.ScanResponse
}

type request struct {
        Attributes  *strelka.Attributes     `json:"attributes,omitempty"`
        Client      string                  `json:"client,omitempty"`
        Id          string                  `json:"id,omitempty"`
        Source      string                  `json:"source,omitempty"`
        Time        int64                   `json:"time,omitempty"`
}

func (s *server) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
        return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (s *server) ScanFile(stream strelka.Frontend_ScanFileServer) error {
        deadline, ok := stream.Context().Deadline()
        if ok == false {
                return nil
        }

        hash := sha256.New()
        id := uuid.New().String()
        keyd := fmt.Sprintf("data:%v", id)
        keye := fmt.Sprintf("event:%v", id)

        var attr *strelka.Attributes
        var req *strelka.Request

        for {
                in, err := stream.Recv()
                if err == io.EOF {
                        break
                }
                if err != nil {
                        return err
                }

                if attr == nil {
                        attr = in.Attributes
                }
                if req == nil {
                        req = in.Request
                }

                hash.Write(in.Data)

                p := s.coordinator.cli.Pipeline()
                p.RPush(keyd, in.Data)
                p.ExpireAt(keyd, deadline)
                if _, err := p.Exec(); err != nil {
                        return err
                }
        }

        if req == nil || attr == nil {
                return nil
        }
        if req.Id == "" {
                req.Id = id
        }

        sha := fmt.Sprintf("hash:%x", hash.Sum(nil))
        em := make(map[string]interface{})
        em["request"] = request{
                Attributes:attr,
                Client:req.Client,
                Id:req.Id,
                Source:req.Source,
                Time:time.Now().Unix(),
        }

        if req.Gatekeeper {
                lrange := s.gatekeeper.cli.LRange(sha, 0, -1).Val()
                if len(lrange) > 0 {
                        for _, e := range lrange {
                                if err := json.Unmarshal([]byte(e), &em); err != nil {
                                        return err
                                }

                                event, err := json.Marshal(em)
                                if err != nil {
                                        return err
                                }

                                resp := &strelka.ScanResponse{
                                        Id:req.Id,
                                        Event:string(event),
                                }

                                s.responses <- resp
                                if err := stream.Send(resp); err != nil {
                                        return err
                                }
                        }

                        if err := s.coordinator.cli.Del(keyd).Err(); err != nil {
                                return err
                        }

                        return nil
                }
        }

        if err := s.coordinator.cli.ZAdd(
                "tasks",
                &redis.Z{
                        Score:  float64(deadline.Unix()),
                        Member: id,
                },
        ).Err(); err != nil {
                return err
        }

        tx := s.gatekeeper.cli.TxPipeline()
        tx.Del(sha)

        for {
                lpop, err := s.coordinator.cli.LPop(keye).Result()
                if err != nil {
                        time.Sleep(250 * time.Millisecond)
                        continue
                }
                if lpop == "FIN" {
                        break
                }

                tx.RPush(sha, lpop)
                if err := json.Unmarshal([]byte(lpop), &em); err != nil {
                        return err
                }

                event, err := json.Marshal(em)
                if err != nil {
                        return err
                }

                resp := &strelka.ScanResponse{
                        Id:req.Id,
                        Event:string(event),
                }

                s.responses <- resp
                if err := stream.Send(resp); err != nil {
                        return err
                }
        }

        tx.Expire(sha, s.gatekeeper.ttl)
        if _, err := tx.Exec(); err != nil {
                return err
        }

        return nil
}

func main() {
        confPath := flag.String(
                "c",
                "/etc/strelka/frontend.yaml",
                "path to frontend config",
        )
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
        if conf.Response.Log != "" {
                go func(){
                        rpc.LogResponses(responses, conf.Response.Log)
                }()
                log.Printf("responses will be logged to %v", conf.Response.Log)
        } else if conf.Response.Report != 0 {
                go func(){
                        rpc.ReportResponses(responses, conf.Response.Report)
                }()
                log.Printf("responses will be reported every %v", conf.Response.Report)
        } else {
                go func(){
                        rpc.DiscardResponses(responses)
                }()
                log.Println("responses will be discarded")
        }

        cd := redis.NewClient(&redis.Options{
                Addr:         conf.Coordinator.Addr,
                DB:           conf.Coordinator.DB,
                PoolSize:     conf.Coordinator.Pool,
                ReadTimeout:  conf.Coordinator.Read,
        })
        if err := cd.Ping().Err(); err != nil {
                log.Fatalf("failed to connect to coordinator: %v", err)
        }

        gk := redis.NewClient(&redis.Options{
                Addr:         conf.Gatekeeper.Addr,
                DB:           conf.Gatekeeper.DB,
                PoolSize:     conf.Gatekeeper.Pool,
                ReadTimeout:  conf.Gatekeeper.Read,
        })
        if err := gk.Ping().Err(); err != nil {
                log.Fatalf("failed to connect to gatekeeper: %v", err)
        }

        s := grpc.NewServer()
        opts := &server{
                coordinator:coord{
                        cli:cd,
                },
                gatekeeper:gate{
                        cli:gk,
                        ttl:conf.Gatekeeper.TTL,
                },
                responses:responses,
        }

        strelka.RegisterFrontendServer(s, opts)
        grpc_health_v1.RegisterHealthServer(s, opts)
        s.Serve(listen)
}
