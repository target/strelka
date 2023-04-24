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
	"strconv"
	"strings"
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
	keyo := fmt.Sprintf("yara_cache_key:%s", id)

	var attr *strelka.Attributes
	var req *strelka.Request

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("receive stream: %w", err)
		}

		if attr == nil {
			attr = in.Attributes
		}

		if req == nil {
			req = in.Request
		}

		p := s.coordinator.cli.Pipeline()

		if attr.YaraCacheKey != "" {
			p.Set(stream.Context(), keyo, attr.YaraCacheKey, time.Until(deadline))
		}

		p.RPush(stream.Context(), keyd, in.Data)
		p.ExpireAt(stream.Context(), keyd, deadline)

		hash.Write(in.Data)
		if len(in.YaraData) > 0 {
			hash.Write(in.YaraData)
			// We're using a different pattern for YARA data, because (unlike the file data) it's not chunked.
			// Additionally, we want to ensure the key stays populated for all exploded sub-documents so that
			// the YARA can be evaluated against them too. Using the 'rpush/rpop' pattern would be cumbersome
			// because we'd have to pass the yara data through the scanners and back into the queue for every
			// sub-document.
			p.SetNX(stream.Context(), keyy, in.YaraData, time.Until(deadline)) // backcompat
		}

		if _, err := p.Exec(stream.Context()); err != nil {
			return fmt.Errorf("redis exec: %w", err)
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
					return fmt.Errorf("unmarshaling: %w", err)
				}

				event, err := json.Marshal(em)
				if err != nil {
					return fmt.Errorf("marshaling: %w", err)
				}

				resp := &strelka.ScanResponse{
					Id:    req.Id,
					Event: string(event),
				}

				s.responses <- resp
				if err := stream.Send(resp); err != nil {
					return fmt.Errorf("send stream: %w", err)
				}
			}

			if err := s.coordinator.cli.Del(stream.Context(), keyd).Err(); err != nil {
				return fmt.Errorf("del key: %w", err)
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
		return fmt.Errorf("sending task: %w", err)
	}

	var tx *redis.Pipeliner
	if s.gatekeeper != nil {
		pipeliner := s.gatekeeper.cli.TxPipeline()
		tx = &pipeliner
		(*tx).Del(stream.Context(), sha)
	}

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
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
			return fmt.Errorf("unexpected result length: %d", len(res))
		}

		lpop := res[1]
		if lpop == "FIN" {
			break
		}

		if tx != nil {
			(*tx).RPush(stream.Context(), sha, lpop)
		}
		if err := json.Unmarshal([]byte(lpop), &em); err != nil {
			return fmt.Errorf("unmarshaling: %w", err)
		}

		event, err := json.Marshal(em)
		if err != nil {
			return fmt.Errorf("marshaling: %w", err)
		}

		resp := &strelka.ScanResponse{
			Id:    req.Id,
			Event: string(event),
		}

		s.responses <- resp
		if err := stream.Send(resp); err != nil {
			return fmt.Errorf("send stream: %w", err)
		}
	}

	if tx != nil {
		(*tx).Expire(stream.Context(), sha, s.gatekeeper.ttl)
		if _, err := (*tx).Exec(stream.Context()); err != nil {
			return fmt.Errorf("gatekeeper tx: %w", err)
		}
	}

	return nil
}

func (s *server) CompileYara(stream strelka.Frontend_CompileYaraServer) error {
	var req *strelka.Request

	deadline, ok := stream.Context().Deadline()
	if ok == false {
		return nil
	}

	id := uuid.New().String()
	keyYaraCompile := fmt.Sprintf("yara:compile:%s", id)
	keyYaraCompileDone := fmt.Sprintf("yara:compile:done:%s", id)

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("receive stream: %w", err)
		}

		if req == nil {
			req = in.Request
		}

		p := s.coordinator.cli.Pipeline()
		if len(in.Data) > 0 {
			// Send for compilation
			p.RPush(stream.Context(), keyYaraCompile, in.Data)
			p.ExpireAt(stream.Context(), keyYaraCompile, deadline)

			if _, err := p.Exec(stream.Context()); err != nil {
				return fmt.Errorf("redis exec: %w", err)
			}
		}
	}

	// skip gatekeeper, we're not sending it

	// send task to backend
	if err := s.coordinator.cli.ZAdd(
		stream.Context(),
		"tasks_compile_yara",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: id,
		},
	).Err(); err != nil {
		return fmt.Errorf("sending task: %w", err)
	}

	var errMsg string

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		res, err := s.coordinator.cli.BLPop(
			stream.Context(),
			5*time.Second,
			keyYaraCompileDone,
		).Result()
		if err != nil {
			if err != redis.Nil {
				// Delay to prevent fast looping over errors
				log.Printf("err: %v\n", err)
				time.Sleep(250 * time.Millisecond)
			}
			continue
		}

		if res[1] == "FIN" {
			break
		}

		if strings.HasPrefix(res[1], "ERROR:") {
			errMsg = strings.Replace(res[1], "ERROR:", "", 1)
			break
		}
	}

	resp := &strelka.CompileYaraResponse{
		Ok:    errMsg == "",
		Error: errMsg,
	}

	if err := stream.Send(resp); err != nil {
		return fmt.Errorf("send stream: %w", err)
	}

	return nil
}

func (s *server) SyncYara(stream strelka.Frontend_SyncYaraServer) error {
	var yaraCacheKey string
	var req *strelka.Request

	deadline, ok := stream.Context().Deadline()
	if ok == false {
		return nil
	}

	id := uuid.New().String()

	var keyYaraHash string
	keyYaraCacheKey := fmt.Sprintf("yara_cache_key:%s", id)
	keyYaraSync := fmt.Sprintf("yara:compile_and_sync:%s", id)
	keyYaraSyncDone := fmt.Sprintf("yara:compile_and_sync:done:%s", id)

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("receive stream: %w", err)
		}

		if req == nil {
			req = in.Request
		}

		if yaraCacheKey == "" {
			yaraCacheKey = in.YaraCacheKey
		}

		p := s.coordinator.cli.Pipeline()
		keyYaraHash = fmt.Sprintf("yara:hash:%s", yaraCacheKey)
		p.Set(stream.Context(), keyYaraCacheKey, yaraCacheKey, time.Until(deadline))

		for _, inData := range in.Data {
			outData, err := json.Marshal(*inData)
			if err != nil {
				return fmt.Errorf("marshaling: %w", err)
			}

			// Send for compilation and sync
			p.RPush(stream.Context(), keyYaraSync, outData)
			p.ExpireAt(stream.Context(), keyYaraSync, deadline)

			if _, err := p.Exec(stream.Context()); err != nil {
				return fmt.Errorf("redis exec: %w", err)
			}
		}

		if len(in.Data) == 0 {
			if _, err := p.Exec(stream.Context()); err != nil {
				return fmt.Errorf("redis exec: %w", err)
			}
		}
	}

	// skip gatekeeper, we're not sending it

	// send task to backend
	if err := s.coordinator.cli.ZAdd(
		stream.Context(),
		"tasks_compile_and_sync_yara",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: id,
		},
	).Err(); err != nil {
		return fmt.Errorf("sending task: %w", err)
	}

	var errMsg string

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		res, err := s.coordinator.cli.BLPop(
			stream.Context(),
			5*time.Second,
			keyYaraSyncDone,
		).Result()
		if err != nil {
			if err != redis.Nil {
				// Delay to prevent fast looping over errors
				log.Printf("err: %v\n", err)
				time.Sleep(250 * time.Millisecond)
			}
			continue
		}

		if res[1] == "FIN" {
			break
		}

		if strings.HasPrefix(res[1], "ERROR:") {
			errMsg = strings.Replace(res[1], "ERROR:", "", 1)
			break
		}
	}

	resp := &strelka.SyncYaraResponse{}

	resp.Synced = 0
	hash, err := s.coordinator.cli.Get(stream.Context(), keyYaraHash).Result()
	if err != nil {
		return fmt.Errorf("getting hash: %w", err)
	}

	synced, err := s.coordinator.cli.Get(stream.Context(), fmt.Sprintf("yara:synced:%s", id)).Result()
	if err != nil {
		return fmt.Errorf("getting sync count: %w", err)
	}

	nSynced, err := strconv.Atoi(synced)
	if err != nil {
		// bye bye bye
		return fmt.Errorf("converting string: %w", err)
	}

	resp.Hash = []byte(hash)
	resp.Error = errMsg
	resp.Synced = int32(nSynced)

	if err := stream.Send(resp); err != nil {
		return fmt.Errorf("send stream: %w", err)
	}

	return nil
}

// Sync Yara using provided (not calculated) hash
// We'll still calculate a hash, in case we can use for error checking.
func (s *server) SyncYaraV2(stream strelka.Frontend_SyncYaraV2Server) error {
	var yaraCacheKey string
	var req *strelka.Request

	deadline, ok := stream.Context().Deadline()
	if ok == false {
		return nil
	}

	id := uuid.New().String()

	var keyYaraHash string
	var keyYaraProvidedHash string
	var yaraProvidedHash string

	keyYaraCacheKey := fmt.Sprintf("yara_cache_key:%s", id)
	keyYaraSync := fmt.Sprintf("yara:compile_and_sync:%s", id)
	keyYaraSyncDone := fmt.Sprintf("yara:compile_and_sync:done:%s", id)

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("receive stream: %w", err)
		}

		if req == nil {
			req = in.Request
		}

		if yaraCacheKey == "" {
			yaraCacheKey = in.YaraCacheKey
			keyYaraProvidedHash = fmt.Sprintf("yara:provided_hash:%s", yaraCacheKey)
		}

		if yaraProvidedHash == "" {
			yaraProvidedHash = in.YaraHash
		}

		p := s.coordinator.cli.Pipeline()
		keyYaraHash = fmt.Sprintf("yara:hash:%s", yaraCacheKey)
		p.Set(stream.Context(), keyYaraCacheKey, yaraCacheKey, time.Until(deadline))

		for _, inData := range in.Data {
			outData, err := json.Marshal(*inData)
			if err != nil {
				return fmt.Errorf("marshaling: %w", err)
			}

			// Send for compilation and sync
			p.RPush(stream.Context(), keyYaraSync, outData)
			p.ExpireAt(stream.Context(), keyYaraSync, deadline)

			if _, err := p.Exec(stream.Context()); err != nil {
				return fmt.Errorf("redis exec: %w", err)
			}
		}

		if len(in.Data) == 0 {
			if _, err := p.Exec(stream.Context()); err != nil {
				return fmt.Errorf("redis exec: %w", err)
			}
		}
	}

	// skip gatekeeper, we're not sending it

	// send task to backend
	if err := s.coordinator.cli.ZAdd(
		stream.Context(),
		"tasks_compile_and_sync_yara",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: id,
		},
	).Err(); err != nil {
		return fmt.Errorf("sending task: %w", err)
	}

	var errMsg string

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		res, err := s.coordinator.cli.BLPop(
			stream.Context(),
			5*time.Second,
			keyYaraSyncDone,
		).Result()
		if err != nil {
			if err != redis.Nil {
				// Delay to prevent fast looping over errors
				log.Printf("err: %v\n", err)
				time.Sleep(250 * time.Millisecond)
			}
			continue
		}

		if res[1] == "FIN" {
			break
		}

		if strings.HasPrefix(res[1], "ERROR:") {
			errMsg = strings.Replace(res[1], "ERROR:", "", 1)
			break
		}
	}

	if errMsg == "" {
		// write provided hash to redis if no errors
		s.coordinator.cli.Set(stream.Context(), keyYaraProvidedHash, yaraProvidedHash, 0)
	}

	resp := &strelka.SyncYaraResponse{}

	resp.Synced = 0
	hash, err := s.coordinator.cli.Get(stream.Context(), keyYaraHash).Result()
	if err != nil {
		return fmt.Errorf("getting hash: %w", err)
	}

	synced, err := s.coordinator.cli.Get(stream.Context(), fmt.Sprintf("yara:synced:%s", id)).Result()
	if err != nil {
		return fmt.Errorf("getting sync count: %w", err)
	}

	nSynced, err := strconv.Atoi(synced)
	if err != nil {
		// bye bye bye
		return fmt.Errorf("converting string: %w", err)
	}

	resp.Hash = []byte(hash)
	resp.Error = errMsg
	resp.Synced = int32(nSynced)

	if err := stream.Send(resp); err != nil {
		return fmt.Errorf("send stream: %w", err)
	}

	return nil
}

func (s *server) ShouldUpdateYara(stream strelka.Frontend_ShouldUpdateYaraServer) error {
	var keyYaraHash string
	var yaraCacheKey string
	var hash []byte

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("receive stream: %w", err)
		}

		if yaraCacheKey == "" {
			yaraCacheKey = in.YaraCacheKey
		}

		if len(hash) == 0 {
			hash = in.Hash
		}

		keyYaraHash = fmt.Sprintf("yara:hash:%s", yaraCacheKey)
	}

	var currentHash string

	res := s.coordinator.cli.Get(stream.Context(), keyYaraHash)
	err := res.Err()
	if err == redis.Nil {
		// do nothing
	} else if err != nil {
		return fmt.Errorf("getting hash key: %w", err)
	}

	currentHash, err = res.Result()
	if err != nil {
		return fmt.Errorf("getting hash key: %w", err)
	}

	if err := stream.Send(&strelka.ShouldUpdateYaraResponse{
		Ok: string(hash) != currentHash,
	}); err != nil {
		return fmt.Errorf("send stream: %w", err)
	}

	return nil
}

// Retrieves the provided hash
func (s *server) GetYaraHash(stream strelka.Frontend_GetYaraHashServer) error {
	var keyYaraHash string
	var yaraCacheKey string

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("receive stream: %w", err)
		}

		if yaraCacheKey == "" {
			yaraCacheKey = in.YaraCacheKey
			keyYaraHash = fmt.Sprintf("yara:provided_hash:%s", yaraCacheKey)
		}
	}

	var currentHash string

	res := s.coordinator.cli.Get(stream.Context(), keyYaraHash)
	err := res.Err()
	if err == redis.Nil {
		// do nothing
	} else if err != nil {
		return fmt.Errorf("getting hash: %w", err)
	}

	currentHash, err = res.Result()
	if err != nil {
		return fmt.Errorf("getting hash: %w", err)
	}

	if err := stream.Send(&strelka.GetYaraHashResponse{
		Hash: currentHash,
	}); err != nil {
		return fmt.Errorf("send stream: %w", err)
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
