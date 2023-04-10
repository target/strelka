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

	// File hashing for event (gatekeeper de-duplication)
	hash := sha256.New()

	// Generate a unique Request ID, mark data and event Redis objects
	id := uuid.New().String()
	keyd := fmt.Sprintf("data:%v", id)
	keye := fmt.Sprintf("event:%v", id)

	var attr *strelka.Attributes
	var req *strelka.Request

	// Recieve gRPC data from client
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

		// Send file data to coordinator Redis
		p := s.coordinator.cli.Pipeline()
		p.RPush(stream.Context(), keyd, in.Data)
		p.ExpireAt(stream.Context(), keyd, deadline)
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

	// Generate file hash
	sha := fmt.Sprintf("hash:%x", hash.Sum(nil))

	// Embed metadata for request in event
	em := make(map[string]interface{})
	em["request"] = request{
		Attributes: attr,
		Client:     req.Client,
		Id:         req.Id,
		Source:     req.Source,
		Time:       time.Now().Unix(),
	}

	// If the client requests gatekeeper caching support & gatekeeper is enabled/present
	if req.Gatekeeper && s.gatekeeper != nil {
		// Check Redis for an event attached to the file hash
		lrange := s.gatekeeper.cli.LRange(stream.Context(), sha, 0, -1).Val()

		// If the gatekeeper has a cached event
		if len(lrange) > 0 {
			for _, e := range lrange {

				// Add cached event data
				if err := json.Unmarshal([]byte(e), &em); err != nil {
					return err
				}

				event, err := json.Marshal(em)
				if err != nil {
					return err
				}

				// Generate a response with cached event
				resp := &strelka.ScanResponse{
					Id:    req.Id,
					Event: string(event),
				}

				// Send gRPC response back to client
				s.responses <- resp
				if err := stream.Send(resp); err != nil {
					return err
				}
			}

			// Delete file data from Redis coordinator
			if err := s.coordinator.cli.Del(stream.Context(), keyd).Err(); err != nil {
				return err
			}

			return nil
		}
	}

	requestInfo, err := json.Marshal(em["request"])
	if err != nil {
		return err
	}

	// Add request task to Redis coordinator with expiration timestamp
	// Backend will be waiting for new tasks to appear in this list
	if err := s.coordinator.cli.ZAdd(
		stream.Context(),
		"tasks",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: requestInfo,
		},
	).Err(); err != nil {
		return err
	}

	var tx redis.Pipeliner
	if s.gatekeeper != nil {
		// Delete any existing event from gatekeeper cache based on file hash
		tx = s.gatekeeper.cli.TxPipeline()
		tx.Del(stream.Context(), sha)
	}

	for {

		// Wait for event to appear in the coordinator
		lpop, err := s.coordinator.cli.LPop(stream.Context(), keye).Result()
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if lpop == "FIN" {
			break
		}

		// Send event to gatekeeper cache (if gatekeeper/resulting tx is present)
		if tx != nil {
			tx.RPush(stream.Context(), sha, lpop)
		}
		if err := json.Unmarshal([]byte(lpop), &em); err != nil {
			return err
		}

		event, err := json.Marshal(em)
		if err != nil {
			return err
		}

		// Generate a response with event data
		resp := &strelka.ScanResponse{
			Id:    req.Id,
			Event: string(event),
		}

		// Send gRPC response back to client
		s.responses <- resp
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	// Set expiration on cached event (if gatekeeper/resulting tx is present)
	if tx != nil {
		tx.Expire(stream.Context(), sha, s.gatekeeper.ttl)
		if _, err := tx.Exec(stream.Context()); err != nil {
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
