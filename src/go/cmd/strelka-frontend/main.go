package main

import (
        "context"
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

type server struct{
        coordinator     *redis.Client
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

                pipe := s.coordinator.Pipeline()
                pipe.RPush(dataKey, incoming.Data)
                pipe.ExpireAt(dataKey, deadline)
                _, _ = pipe.Exec()
                counter++
    	}

        if counter == 0 {
                return nil
        }

        err := s.coordinator.ZAdd(
                "tasks",
                &redis.Z{
                        Score:  float64(deadline.Unix()),
                        Member: id,
                },
        ).Err()
        if err != nil {
                return err
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

        for {
                lpop, err := s.coordinator.LPop(eventKey).Result()
                if err != nil {
                        time.Sleep(250 * time.Millisecond)
                        continue
                }
                if lpop == "FIN" {
                        break
                }

                m := make(map[string]interface{})
                m["request"] = r
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

        s := grpc.NewServer()
        opts := &server{
                coordinator:coordinator,
                responses:responses,
        }
        strelka.RegisterFrontendServer(s, opts)
        grpc_health_v1.RegisterHealthServer(s, opts)
        s.Serve(listen)
}
