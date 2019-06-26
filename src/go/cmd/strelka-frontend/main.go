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

        counter := 0
        id := uuid.New().String()
        dataKey := fmt.Sprintf("data:%v", id)
        eventKey := fmt.Sprintf("event:%v", id)
        hash := sha256.New()
        var incomingRequest *strelka.Request
        var incomingAttributes *strelka.Attributes
        for {
                incoming, err := stream.Recv()
                if err == io.EOF {
                        break
                }
                if err != nil {
                        return err
                }

                if incomingRequest == nil {
                        incomingRequest = incoming.Request
                }
                if incomingAttributes == nil {
                        incomingAttributes = incoming.Attributes
                }

                hash.Write(incoming.Data)
                p := s.coordinator.cli.Pipeline()
                p.RPush(dataKey, incoming.Data)
                p.ExpireAt(dataKey, deadline)
                _, _ = p.Exec()
                counter++
    	}

        if counter == 0 {
                return nil
        }

        if incomingRequest.Id == "" {
                incomingRequest.Id = id
        }

        r := request{
                Attributes:incomingAttributes,
                Client:incomingRequest.Client,
                Id:incomingRequest.Id,
                Source:incomingRequest.Source,
                Time:time.Now().Unix(),
        }

        m := make(map[string]interface{})
        m["request"] = r

        sha := fmt.Sprintf("%x", hash.Sum(nil))
        events := s.gatekeeper.cli.LRange(sha, 0, -1).Val()
        if len(events) > 0 {
                for _, e := range events {
                        if err := json.Unmarshal([]byte(e), &m); err != nil{
                                return err
                        }

                        event, _ := json.Marshal(m)
                        resp := &strelka.ScanResponse{
                                Id:incomingRequest.Id,
                                Event:string(event),
                        }
                        s.responses <- resp
                        if err := stream.Send(resp); err != nil {
                                return err
                        }
                }

                return nil
        }

        err := s.coordinator.cli.ZAdd(
                "tasks",
                &redis.Z{
                        Score:  float64(deadline.Unix()),
                        Member: id,
                },
        ).Err()
        if err != nil {
                return err
        }

        tx := s.gatekeeper.cli.TxPipeline()
        tx.Del(sha)

        for {
                lpop, err := s.coordinator.cli.LPop(eventKey).Result()
                if err != nil {
                        time.Sleep(250 * time.Millisecond)
                        continue
                }
                if lpop == "FIN" {
                        break
                }

                tx.RPush(sha, string(lpop))
                if err := json.Unmarshal([]byte(lpop), &m); err != nil{
                        return err
                }

                event, _ := json.Marshal(m)
                resp := &strelka.ScanResponse{
                        Id:incomingRequest.Id,
                        Event:string(event),
                }
                s.responses <- resp
                if err := stream.Send(resp); err != nil {
                        return err
                }
        }

        tx.Expire(sha, s.gatekeeper.ttl)
        _, _ = tx.Exec()

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

        coordinator := redis.NewClient(&redis.Options{
                Addr:       conf.Coordinator.Addr,
                DB:         conf.Coordinator.Db,
        })
        err = coordinator.Ping().Err()
        if err != nil {
                log.Fatalf("failed to connect to coordinator: %v", err)
        }

        gatekeeper := redis.NewClient(&redis.Options{
                Addr:       conf.Gatekeeper.Addr,
                DB:         conf.Gatekeeper.Db,
        })
        err = gatekeeper.Ping().Err()
        if err != nil {
                log.Fatalf("failed to connect to gatekeeper: %v", err)
        }

        s := grpc.NewServer()
        opts := &server{
                coordinator:coord{
                        cli:coordinator,
                },
                gatekeeper:gate{
                        cli:gatekeeper,
                        ttl:conf.Gatekeeper.Ttl,
                },
                responses:responses,
        }
        strelka.RegisterFrontendServer(s, opts)
        grpc_health_v1.RegisterHealthServer(s, opts)
        s.Serve(listen)
}
