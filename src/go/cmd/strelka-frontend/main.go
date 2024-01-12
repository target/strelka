package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"gopkg.in/yaml.v2"

	grpc_health_v1 "github.com/target/strelka/src/go/api/health"
	"github.com/target/strelka/src/go/api/strelka"
	"github.com/target/strelka/src/go/pkg/rpc"
	"github.com/target/strelka/src/go/pkg/structs"
	tosss3 "github.com/target/strelka/src/go/pkg/tossS3"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

type coord struct {
	cli             *redis.Client
	blockingPopTime time.Duration
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
		if req.Id != "" {
			keyd = fmt.Sprintf("data:%v", req.Id)
			keye = fmt.Sprintf("event:%v", req.Id)
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
		if err := stream.Context().Err(); err != nil {
			return err
		}

		// Wait for event to appear in the coordinator
		lpop, err := s.coordinator.LPop(stream.Context(), keye)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		} else if lpop == "" {
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
	locallog := flag.Bool(
		"locallog",
		true,
		"Boolean to use base local logging for Strelka, defaults to True",
	)

	kafkalog := flag.Bool(
		"kafkalog",
		false,
		"Boolean use Kafka logging, locallog must be false for function to work. Defaults to False",
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

	//Check to see if redundancy toggled for Kafka Producer, defaults to false
	var boolS3 = false
	boolS3, err = strconv.ParseBool(conf.Broker.S3redundancy)
	if err != nil {
		log.Printf("failed to parse boolean for S3 Redundancy, setting to default (False). %v", err)
	}

	responses := make(chan *strelka.ScanResponse, 100)
	defer close(responses)
	if conf.Response.Log != "" {
		if *locallog {
			go func() {
				rpc.LogResponses(responses, conf.Response.Log)
			}()
			log.Printf("responses will be logged to %v", conf.Response.Log)
		}
		if !*locallog && *kafkalog {
			log.Printf("Creating new Kafka producer.")

			// Full kafka configuration documentation:
			// https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
			p, err := kafka.NewProducer(&kafka.ConfigMap{
				"bootstrap.servers":                     conf.Broker.Bootstrap,
				"security.protocol":                     conf.Broker.Protocol,
				"ssl.certificate.location":              conf.Broker.Certlocation,
				"ssl.key.location":                      conf.Broker.Keylocation,
				"ssl.ca.location":                       conf.Broker.Calocation,
				"ssl.endpoint.identification.algorithm": "none",
			})
			if err != nil {
				log.Fatalf("FAILED TO CREATE KAFKA PRODUCER: ERROR %v", err)
			}

			log.Printf("Producer is created, waiting for logs.")

			go func() {
				for e := range p.Events() {
					switch ev := e.(type) {
					case *kafka.Message:
						if ev.TopicPartition.Error != nil {
							log.Printf("Delivery failed to Kafka topic: %v\n", ev.TopicPartition)
							var rawEvent = ev.Value

							//Fail safe for if Kafka delivery production fails, will prevent indefinite streaming to local log
							rpc.LogIndividualResponse(string(rawEvent), conf.Response.Log)
						} else {
							log.Printf("Delivered message to %v\n", ev.TopicPartition)
						}
					}
				}
			}()

			//  Produce messages to topic (asynchronously)
			go func() {
				topic := conf.Broker.Topic
				for r := range responses {
					rawIn := json.RawMessage(r.Event)
					bytes, err := rawIn.MarshalJSON()

					if err != nil {
						log.Fatalf("Unable to marshal byte encoded event, check error message for more details: %v", err)
					}

					if err != nil {
						log.Printf("ERROR %s", err.Error())
						return
					}
					p.Produce(&kafka.Message{
						TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: -1},
						Value:          bytes,
						Headers: []kafka.Header{
							{Key: "@timestamp", Value: []byte(time.Now().Format("2006-01-02T15:04:05-0700"))},
						},
					}, nil)
				}
			}()

			//Optional function to pipe to S3 if change detected in local log file
			if *&boolS3 {
				//Make watcher for seeing if strelka.log file has been changed
				watcher, err := fsnotify.NewWatcher()
				if err != nil {
					log.Fatal(err)
				}

				defer watcher.Close()

				//Watcher for making sure that logs go to S3 if Kafka fails
				err = watcher.Add("/var/log/strelka/strelka.log")
				if err != nil {
					log.Printf("An error occured adding watcher")
					log.Fatal(err)
				}

				// Additional go function added to upload to S3 whenever change has been detected in strelka.log file.
				go func() {
					for {
						select {
						case event, ok := <-watcher.Events:
							if !ok {
								return
							}
							if event.Op&fsnotify.Write == fsnotify.Write {
								localLog, err := os.Open("/var/log/strelka/strelka.log") // For read access.
								if err != nil {
									log.Println("ERROR failed to open strelka.log for size verification:", err)
								}

								logMetadata, err := localLog.Stat()
								if err != nil {
									log.Println("ERROR failed to retrieve strelka.log metadata:", err)
								}

								//Make sure that the strelka.log file hasn't just been truncated before uploading
								if logMetadata.Size() != 0 {
									tosss3.UploadToS3(conf.S3.AccessKey, conf.S3.SecretKey, conf.S3.BucketName, conf.S3.Region, conf.S3.Endpoint)
									log.Println("Change to strelka.log file detected, upload to S3 in progress.")
								}
							}
						case err, ok := <-watcher.Errors:
							if !ok {
								return
							}
							log.Println("ERROR:", err)
						}
					}
				}()

				// Produce messages to topic from logs
				go func() {
					topic := conf.Broker.Topic
					s3logs := tosss3.ListS3BucketContents(conf.S3.AccessKey, conf.S3.SecretKey, conf.S3.BucketName, conf.S3.Region, conf.S3.Endpoint)
					for _, item := range s3logs.Contents {
						// marshall the json message
						log.Println("item key is: " + *item.Key)
						var rawCurrData = tosss3.DownloadFromS3(conf.S3.AccessKey, conf.S3.SecretKey, conf.S3.BucketName, *item.Key, conf.S3.Region, conf.S3.Endpoint)
						for _, splitLog := range bytes.Split(rawCurrData, []byte("\n")) {
							rawIn := json.RawMessage(string(splitLog))
							bytesMess, err := rawIn.MarshalJSON()
							if err != nil {
								log.Printf("Unable to marshal byte encoded event for S3 log, check error message for more details: %v", err)
							}

							p.Produce(&kafka.Message{
								TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: -1},
								Value:          bytesMess,
								Headers: []kafka.Header{
									{Key: "@timestamp", Value: []byte(time.Now().Format("2006-01-02T15:04:05-0700"))},
								},
							}, nil)
						}

					}

					//truncate strelka log file at the end of sending to Kafka
					log.Printf("Beginning to truncate local strelka log.")
					err := os.Truncate("/var/log/strelka/strelka.log", 0)
					if err != nil {
						log.Printf("Failed to truncate strelka.log file after sending messages to Kafka: %v", err)
					}
				}()
			}
		}
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
			cli:             cd,
			blockingPopTime: conf.Coordinator.BlockingPopTime,
		},
		gatekeeper: gatekeeper,
		responses:  responses,
	}

	strelka.RegisterFrontendServer(s, opts)
	grpc_health_v1.RegisterHealthServer(s, opts)
	s.Serve(listen)
}

// LPop consolidate behavior of blocking (BLPop) and standard (LPop) calls based on configured usage.
// An error is returned such that callers can always sleep if an error is returned
// The string result, which is only valid when err is nil, may also be empty in which callers should retry.
func (c coord) LPop(ctx context.Context, key string) (string, error) {
	if c.blockingPopTime > 0 {
		res, err := c.cli.BLPop(ctx, c.blockingPopTime, key).Result()
		if err != nil {
			if err == redis.Nil {
				// Return empty but suppress the error because a consumer of a blocking call should go back to trying
				// if a result isn't available yet.
				return "", nil
			}
			// Return unexpected errors. Consumers should generally wait to retry to prevent fast looping on a
			// misconfig or service interruption.
			return "", err
		}

		if len(res) != 2 {
			return "", fmt.Errorf("unexpected result length")
		}

		return res[1], nil
	}

	lpop, err := c.cli.LPop(ctx, key).Result()
	if err != nil {
		// Return any error, including redis.Nil. Consumers of non-blocking calls should wait to retry.
		return "", err
	}

	return lpop, nil
}
