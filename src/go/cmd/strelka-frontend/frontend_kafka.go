package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/go-redis/redis/v8"

	"github.com/target/strelka/src/go/api/strelka"
)

// ==============================
//  Kafka RAW message structure
// ==============================

type RawKafkaMessage struct {
	Id        string            `json:"id"`
	Filename  string            `json:"filename"`
	DataB64   string            `json:"data_base64"`
	Client    string            `json:"client"`
	Source    string            `json:"source"`
	Time      int64             `json:"time"`
	Meta      map[string]string `json:"meta"`
}

// ==============================
//  Start Kafka Ingest
// ==============================

func (s *server) StartKafkaIngest(bootstrap, topic string) {
	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":        bootstrap,
		"group.id":                "strelka-kafka-ingest",
		"auto.offset.reset":       "earliest",

		// ✅ allow large messages (100MB)
		"max.partition.fetch.bytes": 104857600,
		"fetch.message.max.bytes":   104857600,
	})


	if err != nil {
		log.Fatalf("Kafka consumer init error: %v", err)
	}

	if err := consumer.SubscribeTopics([]string{topic}, nil); err != nil {
		log.Fatalf("Kafka subscribe failed: %v", err)
	}

	log.Printf("🔥 Strelka Kafka Frontend started — consuming from topic: %s", topic)

	for {
		msg, err := consumer.ReadMessage(-1)
		if err != nil {
			log.Printf("Kafka read error: %v", err)
			continue
		}

		var raw RawKafkaMessage
		if err := json.Unmarshal(msg.Value, &raw); err != nil {
			log.Printf("Invalid Kafka message format: %v", err)
			continue
		}

		go s.processRawMessage(raw)
	}
}

// ==============================
//  Process each RAW message
// ==============================

func (s *server) processRawMessage(raw RawKafkaMessage) {
	ctx := context.Background()

	// Decode base64 file
	data, err := base64.StdEncoding.DecodeString(raw.DataB64)
	if err != nil {
		log.Printf("Bad base64 for %s: %v", raw.Id, err)
		return
	}

	keyd := fmt.Sprintf("data:%v", raw.Id)
	keye := fmt.Sprintf("event:%v", raw.Id)

	// Deadline — like ScanFile
	deadline := time.Now().Add(2 * time.Minute)

	// Push file contents to Redis as ONE CHUNK
	p := s.coordinator.cli.Pipeline()
	p.RPush(ctx, keyd, data)
	p.ExpireAt(ctx, keyd, deadline)
	if _, err := p.Exec(ctx); err != nil {
		log.Printf("Redis write error: %v", err)
		return
	}

	log.Printf("📥 Stored file %s in Redis key %s", raw.Id, keyd)

	// Build request metadata
	reqObj := map[string]interface{}{
		"attributes": map[string]interface{}{
			"filename": raw.Filename,
		},
		"client": raw.Client,
		"id":     raw.Id,
		"source": raw.Source,
		"time":   raw.Time,
	}

	// Add to Redis sorted task list
	reqJSON, _ := json.Marshal(reqObj)

	err = s.coordinator.cli.ZAdd(
		ctx,
		"tasks",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: reqJSON,
		},
	).Err()

	if err != nil {
		log.Printf("Failed to add task %s → Redis: %v", raw.Id, err)
		return
	}

	log.Printf("📝 Added task %s to Redis sorted set 'tasks'", raw.Id)

	// Now wait for scanning result
	go s.waitForResult(raw.Id, keye, reqObj)
}

// ==============================
//  Wait for result (same as ScanFile logic)
// ==============================

func (s *server) waitForResult(id, keye string, em map[string]interface{}) {
	ctx := context.Background()

	for {
		lpop, err := s.coordinator.LPop(ctx, keye)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}

		if lpop == "" {
			continue
		}

		if lpop == "FIN" {
			log.Printf("✔️  FIN received for %s", id)
			break
		}

		// Merge event into metadata
		json.Unmarshal([]byte(lpop), &em)

		// prepare final JSON
		event, _ := json.Marshal(em)

		resp := &strelka.ScanResponse{
			Id:    id,
			Event: string(event),
		}

		// Push to frontend responses channel (Kafka logger will pick it)
		s.responses <- resp

		log.Printf("📤 Delivered analysis for %s", id)
	}
}
