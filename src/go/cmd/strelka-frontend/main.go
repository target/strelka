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

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"gopkg.in/yaml.v2"

	grpc_health_v1 "github.com/target/strelka/src/go/api/health"
	"github.com/target/strelka/src/go/api/strelka"
	"github.com/target/strelka/src/go/pkg/rpc"
	"github.com/target/strelka/src/go/pkg/structs"
)

type coord struct {
	cli *redis.Client
}

type gate struct {
	cli *redis.Client
	ttl time.Duration
}

type server struct {
	coordinator coord
	gatekeeper  *gate
	responses   chan<- *strelka.ScanResponse
}

type request struct {
	Attributes *strelka.Attributes `json:"attributes,omitempty"`
	Client     string              `json:"client,omitempty"`
	Id         string              `json:"id,omitempty"`
	Source     string              `json:"source,omitempty"`
	Time       int64               `json:"time,omitempty"`
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
	keyy := fmt.Sprintf("yara:%v", id)

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
		if len(in.YaraData) > 0 {
			hash.Write(in.YaraData)
		}

		p := s.coordinator.cli.Pipeline()
		p.RPush(stream.Context(), keyd, in.Data)
		p.ExpireAt(stream.Context(), keyd, deadline)

		// We're using a different pattern for YARA data, because (unlike the file data) it's not chunked.
		// Additionally, we want to ensure the key stays populated for all exploded sub-documents so that
		// the YARA can be evaluated against them too. Using the 'rpush/rpop' pattern would be cumbersome
		// because we'd have to pass the yara data through the scanners and back into the queue for every
		// sub-document.
		p.SetNX(stream.Context(), keyy, in.YaraData, time.Until(deadline))

		if _, err := p.Exec(stream.Context()); err != nil {
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
		Attributes: attr,
		Client:     req.Client,
		Id:         req.Id,
		Source:     req.Source,
		Time:       time.Now().Unix(),
	}

	if req.Gatekeeper && s.gatekeeper != nil {
		lrange := s.gatekeeper.cli.LRange(stream.Context(), sha, 0, -1).Val()
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
					Id:    req.Id,
					Event: string(event),
				}

				s.responses <- resp
				if err := stream.Send(resp); err != nil {
					return err
				}
			}

			if err := s.coordinator.cli.Del(stream.Context(), keyd).Err(); err != nil {
				return err
			}

			return nil
		}
	}

	if err := s.coordinator.cli.ZAdd(
		stream.Context(),
		"tasks",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: id,
		},
	).Err(); err != nil {
		return err
	}

	var tx *redis.Pipeliner
	if s.gatekeeper != nil {
		pipeliner := s.gatekeeper.cli.TxPipeline()
		tx = &pipeliner
		(*tx).Del(stream.Context(), sha)
	}

	for {
		if err := stream.Context().Err(); err != nil {
			return err
		}

		res, err := s.coordinator.cli.BLPop(stream.Context(), 5*time.Second, keye).Result()
		if err != nil {
			if err != redis.Nil {
				// Delay to prevent fast looping over errors
				time.Sleep(250 * time.Millisecond)
			}
			continue
		}
		// first element will be the name of queue/event, second element is event itself
		if len(res) != 2 {
			return fmt.Errorf("unexpected result length")
		}

		lpop := res[1]
		if lpop == "FIN" {
			break
		}

		if tx != nil {
			(*tx).RPush(stream.Context(), sha, lpop)
		}
		if err := json.Unmarshal([]byte(lpop), &em); err != nil {
			return err
		}

		event, err := json.Marshal(em)
		if err != nil {
			return err
		}

		resp := &strelka.ScanResponse{
			Id:    req.Id,
			Event: string(event),
		}

		s.responses <- resp
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	if tx != nil {
		(*tx).Expire(stream.Context(), sha, s.gatekeeper.ttl)
		if _, err := (*tx).Exec(stream.Context()); err != nil {
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
		log.Fatalf("failed to read config file %s: %v", *confPath, err)
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
		go func() {
			rpc.LogResponses(responses, conf.Response.Log)
		}()
		log.Printf("responses will be logged to %v", conf.Response.Log)
	} else if conf.Response.Report != 0 {
		go func() {
			rpc.ReportResponses(responses, conf.Response.Report)
		}()
		log.Printf("responses will be reported every %v", conf.Response.Report)
	} else {
		go func() {
			rpc.DiscardResponses(responses)
		}()
		log.Println("responses will be discarded")
	}

	cd := redis.NewClient(&redis.Options{
		Addr:        conf.Coordinator.Addr,
		DB:          conf.Coordinator.DB,
		PoolSize:    conf.Coordinator.Pool,
		ReadTimeout: conf.Coordinator.Read,
	})
	if err := cd.Ping(cd.Context()).Err(); err != nil {
		log.Fatalf("failed to connect to coordinator: %v", err)
	}

	var gatekeeper *gate
	if conf.Gatekeeper.Addr != "" {
		gk := redis.NewClient(&redis.Options{
			Addr:        conf.Gatekeeper.Addr,
			DB:          conf.Gatekeeper.DB,
			PoolSize:    conf.Gatekeeper.Pool,
			ReadTimeout: conf.Gatekeeper.Read,
		})
		if err := gk.Ping(gk.Context()).Err(); err != nil {
			log.Fatalf("failed to connect to gatekeeper: %v", err)
		}

		gatekeeper = &gate{
			cli: gk,
			ttl: conf.Gatekeeper.TTL,
		}
	}

	s := grpc.NewServer()
	opts := &server{
		coordinator: coord{
			cli: cd,
		},
		gatekeeper: gatekeeper,
		responses:  responses,
	}

	strelka.RegisterFrontendServer(s, opts)
	grpc_health_v1.RegisterHealthServer(s, opts)
	s.Serve(listen)
}
