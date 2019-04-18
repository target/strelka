package main

import (
        "flag"
        "fmt"
        "io"
        "io/ioutil"
        "log"
        "net"
        "time"
        "encoding/json"

        "github.com/google/uuid"
        "github.com/go-redis/redis"
        "google.golang.org/grpc"
        "gopkg.in/yaml.v2"

        pb "github.com/target/strelka/src/go/api/strelka"
        "github.com/target/strelka/src/go/pkg/rpc"
        "github.com/target/strelka/src/go/pkg/structs"
)

type server struct{
        cache       *redis.Client
        queue       *redis.Client
        responses   chan <- *pb.ScanResponse
}

type request struct {
        Id          string          `json:"id,omitempty"`
        Client      string          `json:"client,omitempty"`
        Source      string          `json:"source,omitempty"`
        Attributes  *pb.Attributes  `json:"attributes,omitempty"`
}

func (s *server) ScanFile(stream pb.Frontend_ScanFileServer) error {
        deadline, ok := stream.Context().Deadline();
        if ok == false {
                return nil
        }

        id := uuid.New().String()
        var inReq *pb.Request
        var inAttr *pb.Attributes
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

    	zadd := s.queue.ZAdd(
                "queue",
                redis.Z{
                        Score:  float64(deadline.Unix()),
                        Member: id,
                },
        )
        if zadd.Err() != nil {
                return zadd.Err()
        }

        r := request{
                Id:inReq.Uid,
                Client:inReq.Client,
                Source:inReq.Source,
                Attributes:inAttr,
        }

        for {
                lpop := s.queue.LPop(id)
                if lpop.Err() != nil {
                        time.Sleep(100 * time.Millisecond)
                        continue
                }
                if lpop.Val() == "FIN" {
                        break
                }

                m := make(map[string]interface{})
                m["time"] = time.Now().Format(time.RFC3339)
                m["request_metadata"] = r
                if err := json.Unmarshal([]byte(lpop.Val()), &m); err != nil{
                        return err
                }
                o, _ := json.Marshal(m)

                resp := &pb.ScanResponse{
                        Uid:inReq.Uid,
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

    responses := make(chan *pb.ScanResponse, 100)
    defer close(responses)
    // this should become an option -- choose the type of response handler and options
    go rpc.LogResponses(responses, conf.Log)

    cache := redis.NewClient(&redis.Options{
            Addr:       conf.Cache.Host,
            DB:         conf.Cache.Db,
    })
    _, err = cache.Ping().Result()
    if err != nil {
            log.Fatalf("failed to connect to cache: %v", err)
    }

    queue := redis.NewClient(&redis.Options{
            Addr:       conf.Queue.Host,
            DB:         conf.Queue.Db,
    })
    _, err = queue.Ping().Result()
    if err != nil {
            log.Fatalf("failed to connect to queue: %v", err)
    }

	s := grpc.NewServer()
    opts := &server{
            cache:cache,
            queue:queue,
            responses:responses,
    }
	pb.RegisterFrontendServer(s, opts)
	s.Serve(listen)
}
